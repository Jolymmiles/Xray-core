package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

// Resolver addresses are checked when the configuration is built, not when
// the client first dials them.
func TestXDNSBuildValidatesResolverAddresses(t *testing.T) {
	build := func(resolver string) error {
		var config XDNS
		raw := `{"domains": [{"name": "t.example.com", "types": [16]}], "resolvers": [` + resolver + `]}`
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			t.Fatal(err)
		}
		_, err := config.Build()
		return err
	}
	for _, resolver := range []string{
		`{"type": "udp", "settings": {"addr": "8.8.8.8:53"}}`,
		`{"type": "udp", "settings": {"addr": "[2001:4860:4860::8888]:53"}}`,
		`{"type": "tcp", "settings": {"addr": "dns.example:853"}}`,
	} {
		if err := build(resolver); err != nil {
			t.Errorf("valid resolver %s rejected: %v", resolver, err)
		}
	}
	for _, resolver := range []string{
		`{"type": "udp", "settings": {"addr": "8.8.8.8"}}`,
		`{"type": "udp", "settings": {"addr": ":53"}}`,
		`{"type": "udp", "settings": {"addr": "8.8.8.8:0"}}`,
		`{"type": "tcp", "settings": {"addr": "8.8.8.8:dns"}}`,
		`{"type": "tcp", "settings": {"addr": ""}}`,
	} {
		if err := build(resolver); err == nil {
			t.Errorf("invalid resolver %s accepted", resolver)
		}
	}
}
