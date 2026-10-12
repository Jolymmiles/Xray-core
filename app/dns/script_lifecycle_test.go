package dns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

// TestDNSQueriesServersBeforeScriptStarts looks a name up before Start, as a
// routing script or an early connection can. The script's pool does not run
// yet, so the configured servers answer; the script answers from Start on.
func TestDNSQueriesServersBeforeScriptStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.lua")
	script := `function HandleDNSQuery(domain, ipv4, ipv6, fake) return nil, nil, "script" end`
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), &Config{Script: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	option := featureDNS.IPOption{IPv4Enable: true}
	wantIP := net.ParseIP("192.0.2.1")
	s.clients = []*Client{{
		server:    &scriptNameServer{name: "test", answers: map[string]net.IP{"good.example": wantIP}, ttl: 60},
		ipOption:  &option,
		timeoutMs: time.Second,
	}}
	lookup := func() (ips []net.IP, err error) {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("lookup panicked: %v", p)
			}
		}()
		ips, _, err = s.LookupIP("good.example", option)
		return ips, err
	}
	if ips, err := lookup(); err != nil || len(ips) != 1 || !ips[0].Equal(wantIP) {
		t.Fatalf("before Start the lookup gave %v, %v; want the server's %v", ips, err, wantIP)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := lookup(); err == nil || !strings.Contains(err.Error(), "script") {
		t.Fatalf("after Start the lookup gave %v; want the script's error", err)
	}
}
