package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
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
