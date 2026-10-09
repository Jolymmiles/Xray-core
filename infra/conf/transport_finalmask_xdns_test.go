package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
)

const testXDNSMask = `{"type": "xdns", "settings": {"domains": [{"names": ["t.example.com"], "types": [16]}], "resolvers": [{"addrs": ["udp://127.0.0.1:53"]}]}}`

// xdns sends and receives plain DNS, so it has to be the innermost UDP mask:
// the last entry of finalmask.udp. A misplaced xdns used to fail only on the
// first dial with "incorrect index", and silently on a server. From TaiLerV's
// sync/upstream-2026-10-02 branch, adapted to the names/addrs schema.
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

// Resolver addresses are checked when the configuration is built, not when
// the client first dials them: an empty address or an out-of-range port must
// be rejected. From TaiLerV's sync/upstream-2026-10-02 branch, adapted to
// the addrs schema. An address without a host, like ":53", reaches the
// resolver on this machine, as it did before the check existed, so it stays
// valid.
func TestXDNSBuildValidatesResolverAddresses(t *testing.T) {
	build := func(addr string) error {
		var config XDNS
		raw := `{"domains": [{"names": ["t.example.com"], "types": [16]}], "resolvers": [{"addrs": [` + addr + `]}]}`
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil {
			return err
		}
		if got := built.(*xdns.Config).Resolvers[0].Addr; addr == `":53"` && got != ":53" {
			t.Errorf("resolver :53 built as %q, want :53", got)
		}
		return nil
	}
	for _, addr := range []string{`"8.8.8.8"`, `"8.8.8.8:53"`, `"udp://8.8.8.8:5353"`, `"tcp://dns.example:853"`, `"[2001:4860:4860::8888]:53"`, `":53"`, `"udp://:53"`, `"tcp://:53"`} {
		if err := build(addr); err != nil {
			t.Errorf("valid resolver %s rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{`""`, `"udp://"`, `"8.8.8.8:0"`, `"8.8.8.8:65536"`, `"quic://8.8.8.8"`} {
		if err := build(addr); err == nil {
			t.Errorf("invalid resolver %s accepted", addr)
		}
	}
}
