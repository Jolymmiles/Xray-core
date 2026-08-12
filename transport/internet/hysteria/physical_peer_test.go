package hysteria

import (
	"net"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
)

func TestHysteriaVirtualConnectionsCarryQUICPeer(t *testing.T) {
	physical := &net.UDPAddr{IP: net.ParseIP("192.0.2.29"), Port: 443}
	connections := []net.Conn{
		&interConn{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1}, physicalPeer: physical},
		&InterConn{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 2}, physicalPeer: physical},
	}
	for _, conn := range connections {
		peer, ok := corenet.PhysicalPeer(conn)
		if !ok || peer.String() != physical.String() {
			t.Fatalf("%T physical peer = %v, ok=%v", conn, peer, ok)
		}
		if conn.RemoteAddr().String() == peer.String() {
			t.Fatalf("%T physical and effective remote were coupled", conn)
		}
	}
}
