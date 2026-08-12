package inbound

import (
	"net"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
)

type presenceWorkerConn struct {
	net.Conn
	remote net.Addr
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
