package conf

import (
	"encoding/hex"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/mtproxy"
)

const (
	defaultMTProxyMaxSecrets = 16
	hardMTProxyMaxSecrets    = 16
	defaultMTProxyPacketSize = 1 << 20
)

type MTProxyClientConfig struct {
	Secret string `json:"secret"`
	Email  string `json:"email"`
	Level  uint32 `json:"level"`
}

type MTProxyUpstreamConfig struct {
	Source               string `json:"source"`
	SecretFile           string `json:"secretFile"`
	ConfigFile           string `json:"configFile"`
	CacheDir             string `json:"cacheDir"`
	RefreshInterval      uint32 `json:"refreshInterval"`
	ProxyTag             string `json:"proxyTag"`
	MaxSessionsPerDC     uint32 `json:"maxSessionsPerDC"`
	MaxClientsPerSession uint32 `json:"maxClientsPerSession"`
	DeliveryQueueDepth   uint32 `json:"deliveryQueueDepth"`
}

type MTProxyFakeTLSConfig struct {
	Only                   bool     `json:"only"`
	Domains                []string `json:"domains"`
	ReplayCacheCapacity    uint32   `json:"replayCacheCapacity"`
	ServerHelloPayloadSize uint32   `json:"serverHelloPayloadSize"`
}

type MTProxyInboundConfig struct {
	Clients              []MTProxyClientConfig `json:"clients"`
	Upstream             MTProxyUpstreamConfig `json:"upstream"`
	FakeTLS              *MTProxyFakeTLSConfig `json:"fakeTLS"`
	MaxSecrets           uint32                `json:"maxSecrets"`
	MaxPacketSize        uint32                `json:"maxPacketSize"`
	HandshakeConcurrency uint32                `json:"handshakeConcurrency"`
}

func (c *MTProxyInboundConfig) Build() (proto.Message, error) {
	maxSecrets := c.MaxSecrets
	if maxSecrets == 0 {
		maxSecrets = defaultMTProxyMaxSecrets
	}
	if maxSecrets > hardMTProxyMaxSecrets {
		return nil, fmt.Errorf("mtproxy: maxSecrets exceeds supported limit %d", hardMTProxyMaxSecrets)
	}
	if len(c.Clients) == 0 || len(c.Clients) > int(maxSecrets) {
		return nil, fmt.Errorf("mtproxy: clients count must be between 1 and %d", maxSecrets)
	}

	users := make([]*protocol.User, 0, len(c.Clients))
	emails := make(map[string]struct{}, len(c.Clients))
	secrets := make(map[[16]byte]struct{}, len(c.Clients))
	for index, client := range c.Clients {
		if client.Email == "" {
			return nil, fmt.Errorf("mtproxy: client %d email is required for API management", index)
		}
		if _, exists := emails[client.Email]; exists {
			return nil, fmt.Errorf("mtproxy: duplicate client email %q", client.Email)
		}
		decoded, err := hex.DecodeString(client.Secret)
		if err != nil || len(decoded) != 16 {
			return nil, fmt.Errorf("mtproxy: client %d secret must contain exactly 32 hex digits", index)
		}
		var raw [16]byte
		copy(raw[:], decoded)
		if _, exists := secrets[raw]; exists {
			return nil, fmt.Errorf("mtproxy: duplicate client secret")
		}
		emails[client.Email] = struct{}{}
		secrets[raw] = struct{}{}
		users = append(users, &protocol.User{Email: client.Email, Level: client.Level, Account: serial.ToTypedMessage(&mtproxy.Account{Secret: decoded})})
	}

	upstream, err := c.Upstream.build()
	if err != nil {
		return nil, err
	}
	fakeTLS, err := c.FakeTLS.build()
	if err != nil {
		return nil, err
	}
	maxPacketSize := c.MaxPacketSize
	if maxPacketSize == 0 {
		maxPacketSize = defaultMTProxyPacketSize
	}
	if maxPacketSize < 4 || maxPacketSize > 4<<20 || maxPacketSize&3 != 0 {
		return nil, fmt.Errorf("mtproxy: invalid maxPacketSize %d", maxPacketSize)
	}
	handshakeConcurrency := c.HandshakeConcurrency
	if handshakeConcurrency == 0 {
		handshakeConcurrency = 128
	}
	if handshakeConcurrency > 4096 {
		return nil, fmt.Errorf("mtproxy: handshakeConcurrency is too large")
	}

	return &mtproxy.Config{Users: users, Upstream: upstream, FakeTls: fakeTLS, MaxSecrets: maxSecrets, MaxPacketSize: maxPacketSize, HandshakeConcurrency: handshakeConcurrency}, nil
}

func (c MTProxyUpstreamConfig) build() (*mtproxy.UpstreamConfig, error) {
	result := &mtproxy.UpstreamConfig{SecretFile: c.SecretFile, ConfigFile: c.ConfigFile, CacheDir: c.CacheDir, RefreshIntervalSeconds: c.RefreshInterval, MaxSessionsPerDc: c.MaxSessionsPerDC, MaxClientsPerSession: c.MaxClientsPerSession, DeliveryQueueDepth: c.DeliveryQueueDepth}
	switch strings.ToLower(c.Source) {
	case "files":
		result.Source = mtproxy.UpstreamSource_UPSTREAM_SOURCE_FILES
		if c.SecretFile == "" || c.ConfigFile == "" || c.CacheDir != "" || c.RefreshInterval != 0 {
			return nil, fmt.Errorf("mtproxy: files upstream requires secretFile/configFile and forbids automatic settings")
		}
	case "telegram":
		result.Source = mtproxy.UpstreamSource_UPSTREAM_SOURCE_TELEGRAM
		if c.CacheDir == "" || c.SecretFile != "" || c.ConfigFile != "" {
			return nil, fmt.Errorf("mtproxy: telegram upstream requires cacheDir and forbids file paths")
		}
		if result.RefreshIntervalSeconds == 0 {
			result.RefreshIntervalSeconds = 86400
		}
		if result.RefreshIntervalSeconds < 60 {
			return nil, fmt.Errorf("mtproxy: refreshInterval must be at least 60 seconds")
		}
	default:
		return nil, fmt.Errorf("mtproxy: upstream source must be files or telegram")
	}
	if c.ProxyTag != "" {
		tag, err := hex.DecodeString(c.ProxyTag)
		if err != nil || len(tag) != 16 {
			return nil, fmt.Errorf("mtproxy: proxyTag must contain exactly 32 hex digits")
		}
		result.ProxyTag = tag
	}
	if result.MaxSessionsPerDc == 0 {
		result.MaxSessionsPerDc = 8
	}
	if result.MaxClientsPerSession == 0 {
		result.MaxClientsPerSession = 4096
	}
	if result.DeliveryQueueDepth == 0 {
		result.DeliveryQueueDepth = 32
	}
	if result.MaxSessionsPerDc > 64 || result.MaxClientsPerSession > 65536 || result.DeliveryQueueDepth > 1024 {
		return nil, fmt.Errorf("mtproxy: upstream pool limits are too large")
	}
	return result, nil
}

func (c *MTProxyFakeTLSConfig) build() (*mtproxy.FakeTLSConfig, error) {
	if c == nil {
		return nil, nil
	}
	if len(c.Domains) == 0 {
		return nil, fmt.Errorf("mtproxy: fakeTLS requires at least one domain")
	}
	domains := make([]string, 0, len(c.Domains))
	seen := make(map[string]struct{}, len(c.Domains))
	for _, domain := range c.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" || strings.ContainsAny(domain, "/: ") {
			return nil, fmt.Errorf("mtproxy: invalid fakeTLS domain %q", domain)
		}
		if _, exists := seen[domain]; exists {
			return nil, fmt.Errorf("mtproxy: duplicate fakeTLS domain %q", domain)
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	replayCapacity := c.ReplayCacheCapacity
	if replayCapacity == 0 {
		replayCapacity = 65536
	}
	payloadSize := c.ServerHelloPayloadSize
	if payloadSize == 0 {
		payloadSize = 1024
	}
	if replayCapacity > 1<<20 || payloadSize > 16384 {
		return nil, fmt.Errorf("mtproxy: invalid fakeTLS limits")
	}
	return &mtproxy.FakeTLSConfig{Enabled: true, Only: c.Only, Domains: domains, ReplayCacheCapacity: replayCapacity, ServerHelloPayloadSize: payloadSize}, nil
}
