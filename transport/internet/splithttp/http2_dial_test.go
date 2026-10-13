package splithttp

import (
	"context"
	"io"
	stdnet "net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// While a TLS handshake hangs, for example because a censor drops the flow
// after the ClientHello, the HTTP/2 client must wait on its one pending dial.
// Go 1.27 made x/net's http2.Transport wrap net/http, which before x/net
// v0.60.0 dialed once per waiting request; that defeats xmux.maxConnections
// and produces the connection burst censors block on. Builds use
// -tags http2legacy, which keeps x/net's own connection pool
// (XTLS/Xray-core#6797).
func TestHTTP2ClientSharesOneDialWhileHandshakeHangs(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var held sync.WaitGroup
	var heldConns sync.Map
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			heldConns.Store(conn, struct{}{})
			held.Go(func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn) // read the ClientHello, never answer
			})
		}
	}()
	// Dials made for net/http's late binding are not bound to the request
	// context, so the server ends the hung handshakes itself.
	t.Cleanup(func() {
		_ = listener.Close()
		<-acceptDone
		heldConns.Range(func(conn, _ any) bool {
			_ = conn.(stdnet.Conn).Close()
			return true
		})
		held.Wait()
	})

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{ServerName: "localhost", Fingerprint: "chrome"},
	}
	port := listener.Addr().(*stdnet.TCPAddr).Port
	client := createHTTPClient(net.TCPDestination(net.LocalHostIP, net.Port(port)), streamSettings).(*DefaultDialerClient)
	if client.httpVersion != "2" {
		t.Fatalf("XHTTP client chose HTTP/%s, want HTTP/2", client.httpVersion)
	}

	const requests = 16
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var waiting sync.WaitGroup
	for range requests {
		waiting.Go(func() {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
			if err != nil {
				t.Error(err)
				return
			}
			if response, err := client.client.Do(request); err == nil {
				_ = response.Body.Close()
			}
		})
	}
	waiting.Wait()

	if dials := accepted.Load(); dials != 1 {
		t.Fatalf("%d requests waiting on a hung TLS handshake opened %d TCP connections, want 1; build with -tags http2legacy (XTLS/Xray-core#6797)", requests, dials)
	}
}
