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
	if got := physicalPeerFromConn(effective); got.IsValid() {
		t.Fatalf("effective RemoteAddr became trusted peer: %s", got)
	}

	raw := corenet.CapturePhysicalPeer(&presenceWorkerConn{
		Conn:   effective,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321},
	})
	wrapped := corenet.PreservePhysicalPeer(raw, effective)
	if got := physicalPeerFromConn(wrapped); got.String() != "192.0.2.9" {
		t.Fatalf("physicalPeerFromConn() = %s, want 192.0.2.9", got)
	}
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

func TestPhysicalPeerFromConnRejectsUnix(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	unix := &presenceWorkerConn{Conn: server, remote: &net.UnixAddr{Name: "/tmp/xray.sock", Net: "unix"}}
	if got := physicalPeerFromConn(corenet.CapturePhysicalPeer(unix)); got.IsValid() {
		t.Fatalf("Unix peer became physical presence: %s", got)
	}
}
