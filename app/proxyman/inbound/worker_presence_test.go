package inbound

import (
	"net"
	"net/netip"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
)

type presenceWorkerConn struct {
	net.Conn
	remote net.Addr
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

func (c *presenceWorkerConn) RemoteAddr() net.Addr { return c.remote }

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
