package mtproxy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func testHandlerConfig(t *testing.T) *Config {
	t.Helper()
	directory := t.TempDir()
	secretPath := filepath.Join(directory, "proxy-secret")
	configPath := filepath.Join(directory, "proxy-multi.conf")
	if err := os.WriteFile(secretPath, bytes.Repeat([]byte{0x41}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(testProxyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Config{
		Users:                nil,
		Upstream:             &UpstreamConfig{Source: UpstreamSource_UPSTREAM_SOURCE_FILES, SecretFile: secretPath, ConfigFile: configPath, MaxSessionsPerDc: 2, MaxClientsPerSession: 16, DeliveryQueueDepth: 2},
		MaxSecrets:           4,
		MaxPacketSize:        1 << 20,
		HandshakeConcurrency: 8,
		FakeTls:              nil,
	}
}

func TestMTProxyHandlerUserManagerAndHardRevoke(t *testing.T) {
	config := testHandlerConfig(t)
	config.Users = nil
	handler, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	first := &protocol.MemoryUser{Email: "first@example", Account: &MemoryAccount{Secret: testSecret(10)}}
	if err := handler.AddUser(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if got := handler.GetUser(context.Background(), first.Email); got == nil || got.Email != first.Email {
		t.Fatalf("GetUser() = %+v", got)
	}
	if handler.GetUsersCount(context.Background()) != 1 || len(handler.GetUsers(context.Background())) != 1 {
		t.Fatal("unexpected user count")
	}

	fingerprint := SecretFingerprintFromSecret(testSecret(10))
	var closed atomic.Int32
	if _, ok := handler.secrets.RegisterSession(fingerprint, 1, func() { closed.Add(1) }); !ok {
		t.Fatal("RegisterSession() failed")
	}
	if err := handler.RemoveUser(context.Background(), first.Email); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatalf("hard revoke close count = %d, want 1", closed.Load())
	}
	if handler.GetUser(context.Background(), first.Email) != nil || handler.GetUsersCount(context.Background()) != 0 {
		t.Fatal("removed user remains visible")
	}
}

func TestMTProxyHandlerRejectsUnsafeDirectProtoLimits(t *testing.T) {
	tests := map[string]func(*Config){
		"secrets":     func(config *Config) { config.MaxSecrets = 17 },
		"packet":      func(config *Config) { config.MaxPacketSize = 8 << 20 },
		"handshakes":  func(config *Config) { config.HandshakeConcurrency = 4097 },
		"body budget": func(config *Config) { config.MaxPacketSize = 4 << 20; config.HandshakeConcurrency = 4096 },
		"sessions":    func(config *Config) { config.Upstream.MaxSessionsPerDc = 65 },
		"clients":     func(config *Config) { config.Upstream.MaxClientsPerSession = 65537 },
		"queue":       func(config *Config) { config.Upstream.DeliveryQueueDepth = 1025 },
		"proxy tag":   func(config *Config) { config.Upstream.ProxyTag = []byte{1, 2, 3} },
		"replay": func(config *Config) {
			config.FakeTls = &FakeTLSConfig{Enabled: true, Domains: []string{"cover.example"}, ReplayCacheCapacity: (1 << 20) + 1}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := testHandlerConfig(t)
			mutate(config)
			if handler, err := New(context.Background(), config); err == nil {
				handler.Close()
				t.Fatal("New() accepted unsafe direct protobuf limits")
			}
		})
	}
}

func TestMTProxyHandlerRejectsDuplicateAndWrongAccount(t *testing.T) {
	config := testHandlerConfig(t)
	config.Users = nil
	handler, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	user := &protocol.MemoryUser{Email: "first@example", Account: &MemoryAccount{Secret: testSecret(20)}}
	if err := handler.AddUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if err := handler.AddUser(context.Background(), user); err == nil {
		t.Fatal("duplicate email accepted")
	}
	if err := handler.AddUser(context.Background(), &protocol.MemoryUser{Email: "other@example", Account: &MemoryAccount{Secret: testSecret(20)}}); err == nil {
		t.Fatal("duplicate secret accepted")
	}
	if err := handler.AddUser(context.Background(), &protocol.MemoryUser{Email: "wrong@example", Account: nil}); err == nil {
		t.Fatal("nil account accepted")
	}
	if err := handler.RemoveUser(context.Background(), "missing@example"); err == nil {
		t.Fatal("missing user removal succeeded")
	}
}
