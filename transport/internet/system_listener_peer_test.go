package internet

import (
	"context"
	"io"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/reality"
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

type peerCloseWriteTestConn struct {
	*peerTestConn
	closedWrite bool
}

func (c *peerCloseWriteTestConn) CloseWrite() error {
	c.closedWrite = true
	return nil
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
	accepted, ok := corenet.AcceptedProxyPeer(conn)
	if !ok || accepted != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("accepted PROXY peer = %s, ok=%v", accepted, ok)
	}
}

func TestPhysicalPeerListenerCapturesAcceptedProxySourceExplicitly(t *testing.T) {
	tests := []struct {
		name   string
		raw    stdnet.Addr
		header []byte
		want   netip.Addr
	}{
		{
			name:   "IPv4",
			raw:    &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.9"), Port: 54321},
			header: []byte("PROXY TCP4 198.51.100.7 203.0.113.1 12345 443\r\nx"),
			want:   netip.MustParseAddr("198.51.100.7"),
		},
		{
			name:   "mapped IPv4",
			raw:    &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.9"), Port: 54321},
			header: []byte("PROXY TCP6 ::ffff:198.51.100.7 2001:db8::1 12345 443\r\nx"),
			want:   netip.MustParseAddr("198.51.100.7"),
		},
		{
			name:   "IPv6",
			raw:    &stdnet.TCPAddr{IP: stdnet.ParseIP("2001:db8::9"), Port: 54321},
			header: []byte("PROXY TCP6 2001:db8::7 2001:db8::1 12345 443\r\nx"),
			want:   netip.MustParseAddr("2001:db8::7"),
		},
		{
			name:   "source equals raw peer",
			raw:    &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.9"), Port: 54321},
			header: []byte("PROXY TCP4 192.0.2.9 203.0.113.1 54321 443\r\nx"),
			want:   netip.MustParseAddr("192.0.2.9"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := proxyListenerConnection(t, test.raw, test.header)
			got, ok := corenet.AcceptedProxyPeer(conn)
			if !ok || got != test.want {
				t.Fatalf("accepted PROXY peer = %s, ok=%v, want %s", got, ok, test.want)
			}
		})
	}
}

func TestPhysicalPeerListenerRejectsUnusableProxySource(t *testing.T) {
	unixHeader, err := (&proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.UnixStream,
		SourceAddr:        &stdnet.UnixAddr{Name: "/run/client.sock", Net: "unix"},
		DestinationAddr:   &stdnet.UnixAddr{Name: "/run/xray.sock", Net: "unix"},
	}).Format()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		header []byte
	}{
		{name: "missing", header: []byte("x")},
		{name: "malformed", header: []byte("PROXY TCP4 invalid 203.0.113.1 12345 443\r\nx")},
		{name: "LOCAL or UNKNOWN", header: []byte("PROXY UNKNOWN\r\nx")},
		{name: "Unix source", header: append(unixHeader, 'x')},
		{name: "unspecified source", header: []byte("PROXY TCP4 0.0.0.0 203.0.113.1 12345 443\r\nx")},
		{name: "loopback source", header: []byte("PROXY TCP4 127.0.0.1 203.0.113.1 12345 443\r\nx")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := proxyListenerConnection(t,
				&stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.9"), Port: 54321},
				test.header,
			)
			if got, ok := corenet.AcceptedProxyPeer(conn); ok || got.IsValid() {
				t.Fatalf("unusable PROXY source became trusted: %s, ok=%v", got, ok)
			}
		})
	}
}

func proxyListenerConnection(t *testing.T, rawPeer stdnet.Addr, payload []byte) stdnet.Conn {
	t.Helper()
	server, client := stdnet.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	listener := &physicalPeerListener{
		Listener: &peerTestListener{conn: &peerTestConn{
			Conn:   server,
			local:  &stdnet.TCPAddr{IP: stdnet.ParseIP("203.0.113.1"), Port: 443},
			remote: rawPeer,
		}},
		proxyProtocol: true,
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = client.Write(payload)
	}()
	return conn
}

func TestPhysicalPeerListenerPreservesRealityCloseWriteAcrossProxyProtocol(t *testing.T) {
	server, client := stdnet.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	raw := &peerCloseWriteTestConn{peerTestConn: &peerTestConn{
		Conn:   server,
		local:  &stdnet.TCPAddr{IP: stdnet.ParseIP("203.0.113.1"), Port: 443},
		remote: &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.9"), Port: 54321},
	}}
	listener := &physicalPeerListener{
		Listener:      &peerTestListener{conn: raw},
		proxyProtocol: true,
	}

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	closeWriter, ok := conn.(reality.CloseWriteConn)
	if !ok {
		t.Fatalf("PROXY physical-peer connection lost reality.CloseWriteConn: %T", conn)
	}
	if err := closeWriter.CloseWrite(); err != nil || !raw.closedWrite {
		t.Fatalf("CloseWrite = %v, delegated = %v", err, raw.closedWrite)
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
