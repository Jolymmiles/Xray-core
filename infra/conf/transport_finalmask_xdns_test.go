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

const testXDNSMask = `{"type": "xdns", "settings": {"domains": [{"name": "t.example.com", "types": [16]}], "resolvers": [{"type": "udp", "settings": {"addr": "127.0.0.1:53"}}]}}`

// xdns sends and receives plain DNS, so it has to be the innermost UDP mask:
// the last entry of finalmask.udp. Misplaced configurations fail at build
// time instead of on the first dial.
func TestXDNSMustBeTheLastUDPMask(t *testing.T) {
	build := func(masks string) error {
		var config StreamConfig
		if err := json.Unmarshal([]byte(`{"network": "kcp", "finalmask": {"udp": [`+masks+`]}}`), &config); err != nil {
			t.Fatal(err)
		}
		_, err := config.Build()
		return err
	}
	salamander := `{"type": "salamander", "settings": {"password": "xdns-order"}}`
	if err := build(salamander + "," + testXDNSMask); err != nil {
		t.Fatalf("xdns as the last UDP mask rejected: %v", err)
	}
	if err := build(testXDNSMask + "," + salamander); err == nil {
		t.Fatal("xdns before another UDP mask accepted")
	}
	if err := build(testXDNSMask + "," + testXDNSMask); err == nil {
		t.Fatal("two xdns masks accepted")
	}
}

// The legacy quicParams.udpHop becomes a udphop mask that dials its own
// sockets, which cannot share the innermost position with xdns.
func TestLegacyQuicUDPHopRejectsXDNS(t *testing.T) {
	var outbound OutboundDetourConfig
	raw := `{"protocol": "freedom", "streamSettings": {"network": "hysteria", "finalmask": {"udp": [` + testXDNSMask + `], "quicParams": {"udpHop": {"ports": "20000-20002"}}}}}`
	if err := json.Unmarshal([]byte(raw), &outbound); err != nil {
		t.Fatal(err)
	}
	if _, err := outbound.Build(); err == nil {
		t.Fatal("legacy quicParams.udpHop combined with xdns was accepted")
	}
}
