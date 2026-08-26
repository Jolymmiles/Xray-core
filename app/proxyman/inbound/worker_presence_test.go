package inbound

import (
	"context"
	"net"
	"net/netip"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type presenceWorkerConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func TestPhysicalPeerFromUDPDestinationRejectsVirtualSources(t *testing.T) {
	if got := physicalPeerFromUDPDestination(corenet.UDPDestination(corenet.ParseAddress("192.0.2.19"), 53)); got != netip.MustParseAddr("192.0.2.19") {
		t.Fatalf("UDP physical peer = %s", got)
	}
	for _, source := range []corenet.Destination{
		corenet.TCPDestination(corenet.ParseAddress("192.0.2.19"), 53),
		corenet.UDPDestination(corenet.DomainAddress("spoofed.example"), 53),
		corenet.UDPDestination(corenet.LocalHostIP, 53),
		{},
	} {
		if got := physicalPeerFromUDPDestination(source); got.IsValid() {
			t.Fatalf("virtual/local source %s became physical peer %s", source, got)
		}
	}
}

func TestPhysicalPeerFromUDPDestinationDoesNotFallBackToEffectiveSource(t *testing.T) {
	effectiveSource := corenet.UDPDestination(corenet.ParseAddress("198.51.100.7"), 53)
	if got := physicalPeerFromUDPDestination(corenet.Destination{}); got.IsValid() {
		t.Fatalf("missing packet provenance used effective source %s as physical peer %s", effectiveSource, got)
	}
}

func (c *presenceWorkerConn) RemoteAddr() net.Addr { return c.remote }

func (c *presenceWorkerConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Conn.LocalAddr()
}

func TestPhysicalPeerFromConnUsesOnlyCapturedProvenance(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	effective := &presenceWorkerConn{
		Conn:   server,
		remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345},
	}
	if got := physicalPeerFromConn(effective, presenceStream(false)); got.IsValid() {
		t.Fatalf("effective RemoteAddr became trusted peer: %s", got)
	}

	raw := corenet.CapturePhysicalPeer(&presenceWorkerConn{
		Conn:   effective,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321},
	})
	wrapped := corenet.PreservePhysicalPeer(raw, effective)
	if got := physicalPeerFromConn(wrapped, presenceStream(false)); got.String() != "192.0.2.9" {
		t.Fatalf("physicalPeerFromConn() = %s, want 192.0.2.9", got)
	}
}

func TestPhysicalPeerFromConnTrustsAcceptedProxyRewrite(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
	}{
		{
			name: "IPv4",
			want: "198.51.100.7",
		},
		{
			name: "mapped IPv4",
			want: "198.51.100.7",
		},
		{
			name: "IPv6",
			want: "2001:db8::7",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			accepted := netip.MustParseAddr(test.want)
			conn := presenceConnection(t,
				&net.UnixAddr{Name: "/run/xray/raw.sock", Net: "unix"},
				accepted,
				&net.TCPAddr{IP: net.ParseIP(test.want), Port: 12345},
			)
			if got := physicalPeerFromConn(conn, presenceStream(true)); got.String() != test.want {
				t.Fatalf("trusted PROXY peer = %s, want %s", got, test.want)
			}
		})
	}
}

func TestPhysicalPeerFromConnKeepsAcceptedProxyPeerAfterEffectiveRewrite(t *testing.T) {
	rewritten := presenceConnection(t,
		&net.UnixAddr{Name: "/run/xray/raw.sock", Net: "unix"},
		netip.MustParseAddr("198.51.100.7"),
		&net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 0},
	)

	if got := physicalPeerFromConn(rewritten, presenceStream(true)); got != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("presence peer = %s, want accepted PROXY source 198.51.100.7", got)
	}
}

func TestPhysicalPeerFromConnIgnoresProxyRewriteWhenDisabled(t *testing.T) {
	conn := presenceConnection(t,
		&net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321},
		netip.MustParseAddr("198.51.100.7"),
		&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345},
	)
	if got := physicalPeerFromConn(conn, presenceStream(false)); got != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("disabled PROXY trusted peer = %s, want raw peer 192.0.2.9", got)
	}
}

func TestPhysicalPeerFromConnRejectsMissingAcceptedProxyPeer(t *testing.T) {
	conn := presenceConnection(t,
		&net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321},
		netip.Addr{},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321},
	)
	if got := physicalPeerFromConn(conn, presenceStream(true)); got.IsValid() {
		t.Fatalf("missing accepted PROXY peer trusted raw/effective fallback: %s", got)
	}
}

func presenceConnection(t *testing.T, rawPeer net.Addr, acceptedProxyPeer netip.Addr, effectivePeer net.Addr) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	conn := &presenceWorkerConn{
		Conn:   server,
		remote: effectivePeer,
		local:  &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443},
	}
	return corenet.WithPeerProvenance(rawPeer, acceptedProxyPeer, conn)
}

type authenticatedPresenceProxy struct {
	provider session.PresenceProvider
	scope    chan session.PresenceScope
}

func (*authenticatedPresenceProxy) Network() []corenet.Network {
	return []corenet.Network{corenet.Network_TCP}
}

func (p *authenticatedPresenceProxy) Process(ctx context.Context, _ corenet.Network, _ stat.Connection, _ routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "test"
	inbound.User = &protocol.MemoryUser{Email: "alice@example.com", Level: 7}
	p.scope <- p.provider.SnapshotPresence(ctx)
	return nil
}

type capturingPresenceProvider struct {
	subject session.PresenceSubject
}

func (p *capturingPresenceProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	inbound := session.InboundFromContext(ctx)
	p.subject = session.PresenceSubject{
		Email: inbound.User.Email, Level: inbound.User.Level, IP: inbound.PhysicalPeer,
	}
	return session.PresenceScope{}
}

func TestTCPWorkerPreservesPhysicalPeerForAuthenticatedSnapshot(t *testing.T) {
	server, client := net.Pipe()
	provider := new(capturingPresenceProvider)
	proxy := &authenticatedPresenceProxy{provider: provider, scope: make(chan session.PresenceScope, 1)}
	worker := &tcpWorker{address: corenet.AnyIP, ctx: context.Background(), proxy: proxy}
	raw := corenet.CapturePhysicalPeer(&presenceWorkerConn{
		Conn: server, remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321},
	})
	effective := &presenceWorkerConn{
		Conn:   raw,
		remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345},
		local:  &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 443},
	}
	worker.callback(corenet.PreservePhysicalPeer(raw, effective))
	_ = client.Close()

	<-proxy.scope
	subject := provider.subject
	if subject.Email != "alice@example.com" || subject.Level != 7 || subject.IP != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("authenticated worker snapshot = %+v", subject)
	}
}

func TestTCPWorkerUsesAcceptedProxyPeerForAuthenticatedSnapshot(t *testing.T) {
	provider := new(capturingPresenceProvider)
	proxy := &authenticatedPresenceProxy{provider: provider, scope: make(chan session.PresenceScope, 1)}
	worker := &tcpWorker{
		address: corenet.AnyIP,
		ctx:     context.Background(),
		proxy:   proxy,
		stream: &internet.MemoryStreamConfig{SocketSettings: &internet.SocketConfig{
			AcceptProxyProtocol: true,
		}},
	}
	worker.callback(presenceConnection(t,
		&net.UnixAddr{Name: "/run/xray/raw.sock", Net: "unix"},
		netip.MustParseAddr("198.51.100.7"),
		&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345},
	))

	<-proxy.scope
	subject := provider.subject
	if subject.Email != "alice@example.com" || subject.Level != 7 || subject.IP != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("authenticated PROXY worker snapshot = %+v", subject)
	}
}

func TestDomainSocketWorkerUsesAcceptedProxyPeerForAuthenticatedSnapshot(t *testing.T) {
	provider := new(capturingPresenceProvider)
	proxy := &authenticatedPresenceProxy{provider: provider, scope: make(chan session.PresenceScope, 1)}
	worker := &dsWorker{
		address: corenet.DomainAddress("/run/xray/raw.sock"),
		ctx:     context.Background(),
		proxy:   proxy,
		stream: &internet.MemoryStreamConfig{SocketSettings: &internet.SocketConfig{
			AcceptProxyProtocol: true,
		}},
	}
	worker.callback(presenceConnection(t,
		&net.UnixAddr{Name: "/run/xray/raw.sock", Net: "unix"},
		netip.MustParseAddr("198.51.100.7"),
		&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345},
	))

	<-proxy.scope
	subject := provider.subject
	if subject.Email != "alice@example.com" || subject.Level != 7 || subject.IP != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("authenticated PROXY domain-socket snapshot = %+v", subject)
	}
}

func TestPhysicalPeerFromConnRejectsUnix(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	unix := &presenceWorkerConn{Conn: server, remote: &net.UnixAddr{Name: "/tmp/xray.sock", Net: "unix"}}
	if got := physicalPeerFromConn(corenet.CapturePhysicalPeer(unix), presenceStream(false)); got.IsValid() {
		t.Fatalf("Unix peer became physical presence: %s", got)
	}
}

func presenceStream(acceptProxyProtocol bool, trustedXForwardedFor ...string) *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{SocketSettings: &internet.SocketConfig{
		AcceptProxyProtocol:  acceptProxyProtocol,
		TrustedXForwardedFor: trustedXForwardedFor,
	}}
}

func TestPhysicalPeerFromConnPrefersTrustedXForwardedFor(t *testing.T) {
	rewritten := presenceConnection(t,
		&net.UnixAddr{Name: "/run/xray/raw.sock", Net: "unix"},
		netip.MustParseAddr("198.51.100.7"),
		&net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 0},
	)

	if got := physicalPeerFromConn(rewritten, presenceStream(true, "CF-Connecting-IP")); got != netip.MustParseAddr("203.0.113.99") {
		t.Fatalf("presence peer = %s, want trusted X-Forwarded-For source 203.0.113.99", got)
	}
}

func TestPhysicalPeerFromConnFallsBackWhenTrustedSourceIsUnusable(t *testing.T) {
	conn := presenceConnection(t,
		&net.UnixAddr{Name: "/run/xray/raw.sock", Net: "unix"},
		netip.MustParseAddr("198.51.100.7"),
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19441},
	)

	if got := physicalPeerFromConn(conn, presenceStream(true, "CF-Connecting-IP")); got != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("unusable effective source = %s, want accepted PROXY source 198.51.100.7", got)
	}
}

func TestTCPWorkerUsesTrustedXForwardedForForAuthenticatedSnapshot(t *testing.T) {
	provider := new(capturingPresenceProvider)
	proxy := &authenticatedPresenceProxy{provider: provider, scope: make(chan session.PresenceScope, 1)}
	worker := &tcpWorker{
		address: corenet.AnyIP,
		ctx:     context.Background(),
		proxy:   proxy,
		stream:  presenceStream(true, "CF-Connecting-IP"),
	}
	worker.callback(presenceConnection(t,
		&net.UnixAddr{Name: "/run/xray/raw.sock", Net: "unix"},
		netip.MustParseAddr("198.51.100.7"),
		&net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 0},
	))

	<-proxy.scope
	subject := provider.subject
	if subject.Email != "alice@example.com" || subject.IP != netip.MustParseAddr("203.0.113.99") {
		t.Fatalf("authenticated trusted-XFF worker snapshot = %+v", subject)
	}
}
