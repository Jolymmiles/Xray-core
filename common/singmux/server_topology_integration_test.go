//go:build integration

package singmux_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestMuxInteropMatrixCoversEveryClientAgainstXray(t *testing.T) {
	scenarios := muxInteropScenarios()
	if len(scenarios) != 24 {
		t.Fatalf("interop scenarios = %d, want 24", len(scenarios))
	}
	seen := make(map[string]bool)
	for _, scenario := range scenarios {
		key := fmt.Sprintf("%s/%s/%s/%t", scenario.peer, scenario.carrier, scenario.network, scenario.padding)
		if seen[key] {
			t.Fatalf("duplicate scenario %s", key)
		}
		seen[key] = true
	}
	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		for _, carrier := range []string{"vless", "trojan"} {
			for _, network := range []string{"tcp", "udp"} {
				for _, padding := range []bool{false, true} {
					key := fmt.Sprintf("%s/%s/%s/%t", peer, carrier, network, padding)
					if !seen[key] {
						t.Errorf("missing Xray-server scenario %s", key)
					}
				}
			}
		}
	}
}

func TestMuxPeerConfigSelectsClientExecutable(t *testing.T) {
	binaries := e2eBinaries{xray: "xray-client", singBox: "sing-box-client", mihomo: "mihomo-client"}
	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		t.Run(peer, func(t *testing.T) {
			binary, arguments, encoded := peerClientConfig(t, binaries, peer, "vless", 23456, 23457, "smux", true, "")
			if binary != peer+"-client" {
				t.Fatalf("client executable = %q, want %q", binary, peer+"-client")
			}
			if len(arguments) == 0 || len(encoded) == 0 {
				t.Fatal("client invocation or configuration is empty")
			}
			if peer == "mihomo" {
				var config struct {
					SOCKSPort int `yaml:"socks-port"`
					Proxies   []struct {
						Type   string `yaml:"type"`
						Server string `yaml:"server"`
						Port   int    `yaml:"port"`
					} `yaml:"proxies"`
				}
				if err := yaml.Unmarshal(encoded, &config); err != nil {
					t.Fatal(err)
				}
				if config.SOCKSPort != 23457 || len(config.Proxies) != 1 {
					t.Fatalf("Mihomo client config = %+v", config)
				}
				proxy := config.Proxies[0]
				if proxy.Type != "vless" || proxy.Server != "127.0.0.1" || proxy.Port != 23456 {
					t.Fatalf("Mihomo proxy target = %+v", proxy)
				}
				return
			}
			var config struct {
				Inbounds []struct {
					Type     string `json:"type"`
					Protocol string `json:"protocol"`
				} `json:"inbounds"`
				Outbounds []struct {
					Type     string `json:"type"`
					Protocol string `json:"protocol"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(encoded, &config); err != nil {
				t.Fatal(err)
			}
			if len(config.Inbounds) != 1 || len(config.Outbounds) != 1 {
				t.Fatal("client must have one SOCKS inbound and one proxy outbound")
			}
			inbound := config.Inbounds[0].Protocol + config.Inbounds[0].Type
			outbound := config.Outbounds[0].Protocol + config.Outbounds[0].Type
			if inbound != "socks" || outbound != "vless" {
				t.Fatalf("client protocols = %q -> %q, want socks -> vless", inbound, outbound)
			}
		})
	}
}
