package http

import (
	"bufio"
	"context"
	"io"
	stdnet "net"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// addressDialer dials one TCP address, whatever the destination.
type addressDialer struct {
	address string
}

func (d addressDialer) Dial(ctx context.Context, _ net.Destination) (stat.Connection, error) {
	var dialer stdnet.Dialer
	return dialer.DialContext(ctx, "tcp", d.address)
}

func (addressDialer) DestIpAddress() net.IP { return nil }

func (addressDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

// A server-first protocol through an HTTP proxy: the proxy's 200 response and
// the server's greeting arrive in one read, and the tunnel hands the greeting
// out before the connection's own bytes. The client's half-close after its
// request must still reach the proxy, as it does when nothing came with the
// response (fix(proxy): preserve TCP half-close end to end).
func TestHTTPTunnelHalfCloseReachesProxy(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
		greeting string
	}{
		{name: "greeting with the response", response: "HTTP/1.1 200 Connection established\r\n\r\n220 greeting\r\n", greeting: "220 greeting\r\n"},
		{name: "no greeting", response: "HTTP/1.1 200 Connection established\r\n\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })

			// The proxy answers CONNECT, then reads what the client sends until
			// the client's half-close.
			received := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					received <- "accept: " + err.Error()
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				if _, err := http.ReadRequest(reader); err != nil {
					received <- "read CONNECT: " + err.Error()
					return
				}
				if _, err := conn.Write([]byte(test.response)); err != nil {
					received <- "write response: " + err.Error()
					return
				}
				request, err := io.ReadAll(reader)
				if err != nil {
					received <- "no half-close: " + err.Error()
					return
				}
				received <- string(request)
			}()

			conn, err := setUpHTTPTunnel(context.Background(), net.TCPDestination(net.LocalHostIP, 3128), "example.com:25", nil, addressDialer{address: listener.Addr().String()}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if test.greeting != "" {
				greeting := make([]byte, len(test.greeting))
				if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != test.greeting {
					t.Fatalf("greeting %q, %v", greeting, err)
				}
			}
			if _, err := conn.Write([]byte("QUIT\r\n")); err != nil {
				t.Fatal(err)
			}
			if err := stat.TryCloseWrite(conn); err != nil {
				t.Fatal(err)
			}
			if got := <-received; got != "QUIT\r\n" {
				t.Fatalf("the proxy received %q, want the request and then the half-close", got)
			}
		})
	}
}
