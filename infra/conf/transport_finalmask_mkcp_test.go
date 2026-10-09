package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/header"
)

// The mKCP "dns" header packs its domain into every packet. A domain that
// would not pack into a well-formed question fails when the configuration
// is built, so `xray run -test` reports it instead of the first listener or
// dial, and an accepted domain reaches the header unchanged.
func TestMkcpLegacyDNSHeaderChecksTheDomainAtBuild(t *testing.T) {
	build := func(value string) (*header.Config, error) {
		raw, err := json.Marshal(map[string]any{
			"network": "kcp",
			"finalmask": map[string]any{"udp": []any{map[string]any{
				"type":     "mkcp-legacy",
				"settings": map[string]any{"header": "dns", "value": value},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		var config StreamConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil {
			return nil, err
		}
		mask, err := built.Udpmasks[0].GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		return mask.(*header.Config), nil
	}

	for value, domain := range map[string]string{
		"":          "www.baidu.com",
		"t.example": "t.example",
		"T.Example": "T.Example",
	} {
		config, err := build(value)
		if err != nil {
			t.Errorf("dns header value %q rejected: %v", value, err)
			continue
		}
		if config.Domain != domain {
			t.Errorf("dns header value %q built domain %q, want %q", value, config.Domain, domain)
		}
	}

	for value, reason := range map[string]string{
		"t.example.":     `invalid domain "t.example.": trailing dot; write "t.example"`,
		"bücher.example": `invalid domain "bücher.example": non-ASCII name; write its punycode form "xn--bcher-kva.example"`,
		".t.example":     `invalid domain ".t.example": empty label`,
	} {
		if _, err := build(value); err == nil {
			t.Errorf("dns header value %q accepted", value)
		} else if !strings.Contains(err.Error(), reason) {
			t.Errorf("dns header value %q error = %q, want it to contain %q", value, err, reason)
		}
	}
}
