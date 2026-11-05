package xdrive

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/tls/refreshtest"
)

// The client builds a TLS config for each connection, with the host as SNI,
// and none of them starts a certificate refresh worker, over TCP or h3.
func TestServiceClientDialsStartNoCertificateRefreshWorkers(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		config, baseline := refreshtest.Config(t, tls.Certificate_ENCIPHERMENT)
		server := newTLSServer(t, &gotls.Config{NextProtos: chromeALPN}, func(w http.ResponseWriter, r *http.Request) {})
		// every host gets a connection of its own, all to the server
		settings := server.settings(config)
		dest := xnet.DestinationFromAddr(server.Listener.Addr())
		settings.Destination = &dest
		client := newServiceClient(context.Background(), new(sync.Map), settings, 5*time.Second, 8)
		for _, host := range []string{"a.example", "b.example", "c.example"} {
			resp, err := client.Get("https://" + host + "/")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		if conns := server.conns.Load(); conns != 3 {
			t.Fatalf("the client opened %d connections, want 3", conns)
		}
		if workers := refreshtest.Workers() - baseline; workers != 0 {
			t.Fatalf("three connections started %d certificate refresh workers", workers)
		}
	})
	t.Run("h3", func(t *testing.T) {
		config, baseline := refreshtest.Config(t, tls.Certificate_ENCIPHERMENT)
		server := newH3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		client := newServiceClient(context.Background(), new(sync.Map), server.settings(config), 5*time.Second, 8)
		for _, url := range []string{"https://www.googleapis.com/drive/v3/files", "https://oauth2.googleapis.com/token"} {
			resp, err := client.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		if conns := server.conns.Load(); conns != 2 {
			t.Fatalf("the client opened %d connections, want 2", conns)
		}
		if workers := refreshtest.Workers() - baseline; workers != 0 {
			t.Fatalf("two connections started %d certificate refresh workers", workers)
		}
	})
}
