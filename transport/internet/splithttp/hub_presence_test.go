package splithttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type splitPresenceConn struct {
	net.Conn
	remote net.Addr
}

func (c *splitPresenceConn) RemoteAddr() net.Addr { return c.remote }

func TestSplitHTTPVirtualConnectionsSeparatePhysicalPeerFromXFF(t *testing.T) {
	tests := []struct {
		name      string
		proto     int
		remote    string
		wantPeer  string
		wantProxy string
		withState bool
	}{
		{name: "H2 connection context", proto: 2, remote: "198.51.100.8:443", wantPeer: "192.0.2.8:8443", wantProxy: "198.51.100.7", withState: true},
		{name: "H3 QUIC request", proto: 3, remote: "192.0.2.9:8443", wantPeer: "192.0.2.9:8443"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &Config{Path: "/sh", XPaddingBytes: &RangeConfig{From: 1, To: 1}}
			var gotPeer, gotProxy, gotRemote string
			handler := &requestHandler{
				config:    config,
				path:      config.GetNormalizedPath(),
				sessionMu: new(sync.Mutex),
				ln: &Listener{
					config: config,
					addConn: func(conn stat.Connection) {
						if peer, ok := corenet.PhysicalPeer(conn); ok {
							gotPeer = peer.String()
						}
						if peer, ok := corenet.AcceptedProxyPeer(conn); ok {
							gotProxy = peer.String()
						}
						gotRemote = conn.RemoteAddr().String()
						_ = conn.Close()
					},
				},
				socketSettings: &internet.SocketConfig{TrustedXForwardedFor: []string{"X-Forwarded-For"}},
			}
			request := httptest.NewRequest(http.MethodGet, "https://example.com/sh/?x_padding=X", nil)
			request.ProtoMajor = test.proto
			request.RemoteAddr = test.remote
			request.Header.Set("X-Forwarded-For", "203.0.113.99")
			if test.withState {
				server, client := net.Pipe()
				t.Cleanup(func() {
					_ = server.Close()
					_ = client.Close()
				})
				source := corenet.WithPeerProvenance(
					&net.TCPAddr{IP: net.ParseIP("192.0.2.8"), Port: 8443},
					netip.MustParseAddr("198.51.100.7"),
					&splitPresenceConn{Conn: server, remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.8"), Port: 8443}},
				)
				request = request.WithContext(internet.ContextWithPhysicalPeer(context.Background(), source))
			}

			handler.ServeHTTP(httptest.NewRecorder(), request)
			if gotPeer != test.wantPeer {
				t.Fatalf("physical peer = %q, want %q", gotPeer, test.wantPeer)
			}
			if gotProxy != test.wantProxy {
				t.Fatalf("accepted PROXY peer = %q, want %q", gotProxy, test.wantProxy)
			}
			if gotRemote != "203.0.113.99:0" {
				t.Fatalf("effective remote = %q, want XFF", gotRemote)
			}
		})
	}
}
