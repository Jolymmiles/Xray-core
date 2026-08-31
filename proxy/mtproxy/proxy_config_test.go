package mtproxy

import (
	"strings"
	"testing"
)

func TestParseProxyConfigClustersAndDefault(t *testing.T) {
	input := strings.NewReader(`
# current Telegram proxy list
proxy_for 1 149.154.175.50:8888;
proxy_for 1 149.154.175.51:8888;
proxy_for -2 [2001:db8::2]:443;
proxy 149.154.167.40:8888;
default 1;
`)
	config, err := ParseProxyConfig(input, 16, 8)
	if err != nil {
		t.Fatalf("ParseProxyConfig() error = %v", err)
	}
	if config.DefaultDC != 1 {
		t.Fatalf("DefaultDC = %d, want 1", config.DefaultDC)
	}
	if got := config.Endpoints(1); len(got) != 2 || got[0].Host != "149.154.175.50" || got[1].Port != 8888 {
		t.Fatalf("Endpoints(1) = %+v", got)
	}
	if got := config.Endpoints(-2); len(got) != 1 || got[0].Host != "2001:db8::2" || got[0].Port != 443 {
		t.Fatalf("Endpoints(-2) = %+v", got)
	}
	if got := config.Endpoints(99); len(got) != 2 {
		t.Fatalf("fallback Endpoints(99) = %+v, want default DC endpoints", got)
	}
	if got := config.Endpoints(0); len(got) != 1 || got[0].Host != "149.154.167.40" {
		t.Fatalf("Endpoints(0) = %+v", got)
	}
}

func TestParseProxyConfigRejectsMalformedAndBounds(t *testing.T) {
	tests := []string{
		"proxy_for 40000 127.0.0.1:1;",
		"proxy_for 1 127.0.0.1:0;",
		"proxy_for 1 missing-port;",
		"proxy_for 1 127.0.0.1:80",
		"default 2;",
		"unknown 1 127.0.0.1:80;",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseProxyConfig(strings.NewReader(input), 2, 2); err == nil {
				t.Fatal("ParseProxyConfig() accepted malformed input")
			}
		})
	}

	if _, err := ParseProxyConfig(strings.NewReader("proxy_for 1 a:1;\nproxy_for 2 b:2;"), 8, 1); err == nil {
		t.Fatal("ParseProxyConfig() accepted too many clusters")
	}
	if _, err := ParseProxyConfig(strings.NewReader("proxy_for 1 a:1;\nproxy_for 1 b:2;"), 1, 8); err == nil {
		t.Fatal("ParseProxyConfig() accepted too many targets")
	}
}
