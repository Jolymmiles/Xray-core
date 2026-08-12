package finalmask

import (
	"net"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
)

type physicalPeerMask struct{}

func (physicalPeerMask) TCP() {}

func (physicalPeerMask) WrapConnClient(conn net.Conn) (net.Conn, error) {
	return &physicalPeerMaskConn{Conn: conn}, nil
}

func (physicalPeerMask) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return &physicalPeerMaskConn{Conn: conn}, nil
}

type physicalPeerMaskConn struct {
	net.Conn
}

func TestTCPMaskPreservesPhysicalPeer(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	source := corenet.CapturePhysicalPeer(&peerAddressConn{
		Conn:   server,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.19"), Port: 8443},
	})
	manager := NewTcpmaskManager([]Tcpmask{physicalPeerMask{}})
	wrapper, err := manager.WrapConnServer(source)
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := corenet.PhysicalPeer(wrapper)
	if !ok || peer.String() != "192.0.2.19:8443" {
		t.Fatalf("physical peer after mask = %v, ok=%v", peer, ok)
	}
}

type peerAddressConn struct {
	net.Conn
	remote net.Addr
}

func (c *peerAddressConn) RemoteAddr() net.Addr { return c.remote }
