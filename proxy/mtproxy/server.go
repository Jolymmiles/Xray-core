package mtproxy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Handler struct {
	config *Config
	ctx    context.Context
	cancel context.CancelFunc

	secrets            *SecretRegistry
	usersMu            sync.RWMutex
	users              map[string]*protocol.MemoryUser
	fingerprintByEmail map[string]SecretFingerprint
	emailByFingerprint map[SecretFingerprint]string

	upstream       atomic.Pointer[UpstreamData]
	middle         *middleManager
	telegramSource *TelegramUpstreamSource
	fakeTLS        *FakeTLSAuthenticator
	handshakeSlots chan struct{}

	closeOnce sync.Once
}

func New(ctx context.Context, config *Config) (*Handler, error) {
	if config == nil || config.Upstream == nil {
		return nil, fmt.Errorf("mtproxy: missing configuration")
	}
	maxSecrets := config.MaxSecrets
	if maxSecrets == 0 {
		maxSecrets = 16
	}
	registry, err := NewSecretRegistry(int(maxSecrets))
	if err != nil {
		return nil, err
	}
	if config.MaxPacketSize == 0 {
		config.MaxPacketSize = 1 << 20
	}
	if config.HandshakeConcurrency == 0 {
		config.HandshakeConcurrency = 128
	}
	if config.Upstream.MaxSessionsPerDc == 0 {
		config.Upstream.MaxSessionsPerDc = 8
	}
	if config.Upstream.MaxClientsPerSession == 0 {
		config.Upstream.MaxClientsPerSession = 4096
	}
	if config.Upstream.DeliveryQueueDepth == 0 {
		config.Upstream.DeliveryQueueDepth = 32
	}

	handlerContext, cancel := context.WithCancel(ctx)
	handler := &Handler{
		config:             config,
		ctx:                handlerContext,
		cancel:             cancel,
		secrets:            registry,
		users:              make(map[string]*protocol.MemoryUser, maxSecrets),
		fingerprintByEmail: make(map[string]SecretFingerprint, maxSecrets),
		emailByFingerprint: make(map[SecretFingerprint]string, maxSecrets),
		handshakeSlots:     make(chan struct{}, config.HandshakeConcurrency),
	}
	for _, user := range config.Users {
		memoryUser, err := user.ToMemoryUser()
		if err != nil {
			handler.Close()
			return nil, fmt.Errorf("mtproxy: parse client: %w", err)
		}
		if err := handler.AddUser(ctx, memoryUser); err != nil {
			handler.Close()
			return nil, err
		}
	}

	var upstream *UpstreamData
	switch config.Upstream.Source {
	case UpstreamSource_UPSTREAM_SOURCE_FILES:
		upstream, err = LoadFileUpstream(config.Upstream.SecretFile, config.Upstream.ConfigFile)
	case UpstreamSource_UPSTREAM_SOURCE_TELEGRAM:
		refresh := time.Duration(config.Upstream.RefreshIntervalSeconds) * time.Second
		handler.telegramSource, err = NewTelegramUpstreamSource(config.Upstream.CacheDir, refresh)
		if err == nil {
			upstream, err = handler.telegramSource.LoadInitial(handlerContext)
		}
	default:
		err = fmt.Errorf("mtproxy: unsupported upstream source")
	}
	if err != nil {
		handler.Close()
		return nil, err
	}
	handler.upstream.Store(upstream)
	handler.middle, err = newMiddleManager(config.Upstream, &handler.upstream, int(config.MaxPacketSize))
	if err != nil {
		handler.Close()
		return nil, err
	}
	if handler.telegramSource != nil {
		go handler.telegramSource.Run(handlerContext, func(data *UpstreamData) { handler.upstream.Store(data) })
	}

	if config.FakeTls != nil && config.FakeTls.Enabled {
		replay, err := NewReplayCache(int(config.FakeTls.ReplayCacheCapacity), 48*time.Hour)
		if err != nil {
			handler.Close()
			return nil, err
		}
		handler.fakeTLS = NewFakeTLSAuthenticator(registry, config.FakeTls.Domains, replay, nil)
	}
	return handler, nil
}

func (h *Handler) Network() []corenet.Network { return []corenet.Network{corenet.Network_TCP} }

func (h *Handler) Process(ctx context.Context, network corenet.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	if network != corenet.Network_TCP {
		return fmt.Errorf("mtproxy: unsupported network %s", network)
	}
	return h.processConnection(ctx, connection, dispatcher)
}

func (h *Handler) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	if user == nil || user.Email == "" {
		return fmt.Errorf("mtproxy: user email is required")
	}
	account, ok := user.Account.(*MemoryAccount)
	if !ok || account == nil {
		return fmt.Errorf("mtproxy: user has an invalid account")
	}
	fingerprint := SecretFingerprintFromSecret(account.Secret)

	h.usersMu.Lock()
	defer h.usersMu.Unlock()
	if _, exists := h.users[user.Email]; exists {
		return fmt.Errorf("mtproxy: duplicate user email %q", user.Email)
	}
	if existing, exists := h.emailByFingerprint[fingerprint]; exists {
		return fmt.Errorf("mtproxy: secret already belongs to %q", existing)
	}
	if _, added, err := h.secrets.Add(account.Secret); err != nil {
		return err
	} else if !added {
		return fmt.Errorf("mtproxy: duplicate client secret")
	}
	copyUser := *user
	h.users[user.Email] = &copyUser
	h.fingerprintByEmail[user.Email] = fingerprint
	h.emailByFingerprint[fingerprint] = user.Email
	return nil
}

func (h *Handler) RemoveUser(_ context.Context, email string) error {
	h.usersMu.Lock()
	defer h.usersMu.Unlock()
	if _, exists := h.users[email]; !exists {
		return fmt.Errorf("mtproxy: user %q not found", email)
	}
	fingerprint := h.fingerprintByEmail[email]
	delete(h.users, email)
	delete(h.fingerprintByEmail, email)
	delete(h.emailByFingerprint, fingerprint)
	if !h.secrets.Delete(fingerprint) {
		return fmt.Errorf("mtproxy: secret for %q was not registered", email)
	}
	return nil
}

func (h *Handler) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	h.usersMu.RLock()
	defer h.usersMu.RUnlock()
	user := h.users[email]
	if user == nil {
		return nil
	}
	copyUser := *user
	return &copyUser
}

func (h *Handler) GetUsers(context.Context) []*protocol.MemoryUser {
	h.usersMu.RLock()
	defer h.usersMu.RUnlock()
	result := make([]*protocol.MemoryUser, 0, len(h.users))
	for _, user := range h.users {
		copyUser := *user
		result = append(result, &copyUser)
	}
	return result
}

func (h *Handler) GetUsersCount(context.Context) int64 {
	h.usersMu.RLock()
	defer h.usersMu.RUnlock()
	return int64(len(h.users))
}

func (h *Handler) Close() error {
	h.closeOnce.Do(func() {
		h.cancel()
		if h.middle != nil {
			h.middle.Close()
		}
	})
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config any) (any, error) {
		return New(ctx, config.(*Config))
	}))
}
