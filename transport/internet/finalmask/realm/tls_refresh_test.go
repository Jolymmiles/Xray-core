package realm

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/tls/refreshtest"
)

// Each realm connection builds a client of the realm server, whose TLS config
// starts no certificate refresh worker that would outlive the connection.
func TestNewClientStartsNoCertificateRefreshWorkers(t *testing.T) {
	config, baseline := refreshtest.Config(t, tls.Certificate_ENCIPHERMENT)
	for range 3 {
		if client := NewClient("https", "realm.example", "443", "token", config); client == nil {
			t.Fatal("NewClient returned nil")
		}
	}
	if workers := refreshtest.Workers() - baseline; workers != 0 {
		t.Fatalf("three realm clients started %d certificate refresh workers", workers)
	}
}
