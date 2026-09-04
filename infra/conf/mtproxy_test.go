package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/mtproxy"
)

func validMTProxyConfig() *MTProxyInboundConfig {
	return &MTProxyInboundConfig{
		Clients: []MTProxyClientConfig{{Secret: "00112233445566778899aabbccddeeff", Email: "client@example"}},
		Upstream: MTProxyUpstreamConfig{
			Source:     "files",
			SecretFile: "/etc/xray/mtproxy/proxy-secret",
			ConfigFile: "/etc/xray/mtproxy/proxy-multi.conf",
			ProxyTag:   "ffeeddccbbaa99887766554433221100",
		},
		MaxSecrets:    16,
		MaxPacketSize: 1 << 20,
	}
}

func TestMTProxyInboundConfigBuildFiles(t *testing.T) {
	built, err := validMTProxyConfig().Build()
	if err != nil {
		t.Fatal(err)
	}
	config, ok := built.(*mtproxy.Config)
	if !ok {
		t.Fatalf("Build() type = %T", built)
	}
	if len(config.Users) != 1 || config.Upstream.Source != mtproxy.UpstreamSource_UPSTREAM_SOURCE_FILES || config.Upstream.SecretFile == "" || len(config.Upstream.ProxyTag) != 16 {
		t.Fatalf("built config = %+v", config)
	}
}

func TestMTProxyInboundConfigBuildTelegramAutomatic(t *testing.T) {
	config := validMTProxyConfig()
	config.Upstream = MTProxyUpstreamConfig{
		Source:          "telegram",
		CacheDir:        "/var/lib/xray/mtproxy",
		RefreshInterval: 86400,
	}
	config.FakeTLS = &MTProxyFakeTLSConfig{Only: true, Domains: []string{"cover.example"}}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	result := built.(*mtproxy.Config)
	if result.Upstream.Source != mtproxy.UpstreamSource_UPSTREAM_SOURCE_TELEGRAM || result.FakeTls == nil || !result.FakeTls.Only {
		t.Fatalf("built config = %+v", result)
	}
}

func TestMTProxyInboundJSONConfig(t *testing.T) {
	raw := `{
		"clients": [{"secret": "00112233445566778899aabbccddeeff", "email": "json@example"}],
		"upstream": {
			"source": "telegram",
			"cacheDir": "/var/lib/xray/mtproxy",
			"refreshInterval": 86400
		},
		"fakeTLS": {"only": true, "domains": ["cover.example"]}
	}`
	parsed := new(MTProxyInboundConfig)
	if err := json.Unmarshal([]byte(raw), parsed); err != nil {
		t.Fatal(err)
	}
	built, err := parsed.Build()
	if err != nil {
		t.Fatal(err)
	}
	config := built.(*mtproxy.Config)
	if len(config.Users) != 1 || config.Users[0].Email != "json@example" || config.Upstream.Source != mtproxy.UpstreamSource_UPSTREAM_SOURCE_TELEGRAM {
		t.Fatalf("JSON config = %+v", config)
	}
}

func TestMTProxyInboundConfigRejectsInvalidSettings(t *testing.T) {
	tests := map[string]func(*MTProxyInboundConfig){
		"no clients":           func(config *MTProxyInboundConfig) { config.Clients = nil },
		"short client secret":  func(config *MTProxyInboundConfig) { config.Clients[0].Secret = "abcd" },
		"missing email":        func(config *MTProxyInboundConfig) { config.Clients[0].Email = "" },
		"unknown source":       func(config *MTProxyInboundConfig) { config.Upstream.Source = "other" },
		"files missing config": func(config *MTProxyInboundConfig) { config.Upstream.ConfigFile = "" },
		"files with cache":     func(config *MTProxyInboundConfig) { config.Upstream.CacheDir = "/tmp/cache" },
		"telegram with files": func(config *MTProxyInboundConfig) {
			config.Upstream.Source = "telegram"
			config.Upstream.CacheDir = "/tmp/cache"
		},
		"body budget":             func(config *MTProxyInboundConfig) { config.MaxPacketSize = 4 << 20; config.HandshakeConcurrency = 4096 },
		"bad proxy tag":           func(config *MTProxyInboundConfig) { config.Upstream.ProxyTag = "abcd" },
		"fake TLS without domain": func(config *MTProxyInboundConfig) { config.FakeTLS = &MTProxyFakeTLSConfig{Only: true} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validMTProxyConfig()
			mutate(config)
			if _, err := config.Build(); err == nil {
				t.Fatal("Build() accepted invalid settings")
			}
		})
	}
}

func TestMTProxyConfigRejectsInvalidFakeTLSDomains(t *testing.T) {
	for _, domain := range []string{"cover\texample", "пример.рф", strings.Repeat("a", 254)} {
		config := validMTProxyConfig()
		config.FakeTLS = &MTProxyFakeTLSConfig{Domains: []string{domain}}
		if _, err := config.Build(); err == nil {
			t.Errorf("accepted invalid domain %q", domain)
		}
	}
}
