package inbound

import (
	"net"
	"testing"
)

type rawPeerTestConn struct {
	net.Conn
	remote net.Addr
	raw    net.Addr
}

func (c *rawPeerTestConn) RemoteAddr() net.Addr    { return c.remote }
func (c *rawPeerTestConn) RawRemoteAddr() net.Addr { return c.raw }

func TestCarrierSourceFromConnPrefersRawPeer(t *testing.T) {
	conn := &rawPeerTestConn{
		remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345},
		raw:    &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321},
	}

	got := carrierSourceFromConn(conn)
	if got.Address.String() != "192.0.2.9" || got.Port.Value() != 54321 {
		t.Fatalf("carrierSourceFromConn() = %s; want tcp:192.0.2.9:54321", got)
	}
}
