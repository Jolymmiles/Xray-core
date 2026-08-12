package internet

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
)

type peerTestConn struct {
	stdnet.Conn
	local  stdnet.Addr
	remote stdnet.Addr
}

func (c *peerTestConn) LocalAddr() stdnet.Addr  { return c.local }
func (c *peerTestConn) RemoteAddr() stdnet.Addr { return c.remote }

type peerTestListener struct {
	conn stdnet.Conn
}

func (l *peerTestListener) Accept() (stdnet.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	conn := l.conn
	l.conn = nil
	return conn, nil
}

func (*peerTestListener) Close() error      { return nil }
func (*peerTestListener) Addr() stdnet.Addr { return &stdnet.TCPAddr{} }

func TestPhysicalPeerListenerFreezesPeerBeforeProxyRewrite(t *testing.T) {
	server, client := stdnet.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	rawIP := stdnet.ParseIP("192.0.2.9")
	listener := &physicalPeerListener{
		Listener: &peerTestListener{conn: &peerTestConn{
			Conn:   server,
			local:  &stdnet.TCPAddr{IP: stdnet.ParseIP("203.0.113.1"), Port: 443},
			remote: &stdnet.TCPAddr{IP: rawIP, Port: 54321},
		}},
		proxyProtocol: true,
	}

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	rawIP[0] ^= 0xff
	peer, ok := corenet.PhysicalPeer(conn)
	if !ok || peer.String() != "192.0.2.9:54321" {
		t.Fatalf("physical peer before PROXY read = %v, ok=%v", peer, ok)
	}

	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 198.51.100.7 203.0.113.1 12345 443\r\nx"))
	}()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	if got := conn.RemoteAddr().String(); got != "198.51.100.7:12345" {
		t.Fatalf("effective remote after PROXY = %s", got)
	}
	peer, ok = corenet.PhysicalPeer(conn)
	if !ok || peer.String() != "192.0.2.9:54321" {
		t.Fatalf("physical peer after PROXY read = %v, ok=%v", peer, ok)
	}
}

func TestPreservePhysicalPeerAcrossConnectionWrapper(t *testing.T) {
	server, client := stdnet.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	raw := corenet.CapturePhysicalPeer(&peerTestConn{
		Conn:   server,
		remote: &stdnet.TCPAddr{IP: stdnet.ParseIP("2001:db8::7"), Port: 443, Zone: "en0"},
	})
	wrapper := &peerTestConn{Conn: raw, remote: &stdnet.TCPAddr{IP: stdnet.ParseIP("198.51.100.7"), Port: 12345}}
	preserved := corenet.PreservePhysicalPeer(raw, wrapper)

	peer, ok := corenet.PhysicalPeer(preserved)
	if !ok || peer.String() != "[2001:db8::7%en0]:443" {
		t.Fatalf("preserved physical peer = %v, ok=%v", peer, ok)
	}
	if got := preserved.RemoteAddr().String(); got != "198.51.100.7:12345" {
		t.Fatalf("wrapper effective remote = %s", got)
	}
}

func TestDefaultListenerWithoutProxyKeepsNativeTCPListener(t *testing.T) {
	listener, err := new(DefaultListener).Listen(context.Background(), &stdnet.TCPAddr{
		IP: stdnet.ParseIP("127.0.0.1"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if _, ok := listener.(*stdnet.TCPListener); !ok {
		t.Fatalf("listener type = %T, want *net.TCPListener", listener)
	}
}
