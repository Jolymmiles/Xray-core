package dokodemo

import (
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// recordingPacketConn counts the datagrams written to it.
type recordingPacketConn struct {
	mu     sync.Mutex
	writes int
	closed bool
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, stdnet.Addr, error) { select {} }
func (c *recordingPacketConn) WriteTo(p []byte, _ stdnet.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return len(p), nil
}

func (c *recordingPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (*recordingPacketConn) LocalAddr() stdnet.Addr           { return &stdnet.UDPAddr{} }
func (*recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

// Replies from the session's own target must go out of the socket the session
// opened for it, whatever type holds the reply's address. Hysteria's UDP
// reader stores reply addresses in the packet buffer's slab, and a map keyed
// by net.Destination compares those by pointer, so each reply missed the
// entry and opened another FakeUDP socket.
func TestPacketWriterReusesTargetSocketForSlabAddresses(t *testing.T) {
	ipv4 := [4]byte{192, 0, 2, 1}
	ipv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	for _, test := range []struct {
		name   string
		target net.Destination
		set    func(*buf.Buffer)
	}{
		{name: "ipv4", target: net.UDPDestination(net.IPv4Address(ipv4), 443), set: func(b *buf.Buffer) { b.SetManagedUDPIPv4(ipv4, 443) }},
		{name: "ipv6", target: net.UDPDestination(net.IPv6Address(ipv6), 443), set: func(b *buf.Buffer) { b.SetManagedUDPIPv6(ipv6, 443) }},
		{name: "plain", target: net.UDPDestination(net.IPv6Address(ipv6), 443), set: func(b *buf.Buffer) {
			b.SetManagedUDPDestination(net.UDPDestination(net.IPv6Address(ipv6), 443))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := &recordingPacketConn{}
			writer := NewPacketWriter(target, &test.target, 0, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 9}).(*PacketWriter)
			// A reply whose address yields no key takes writer.conn; keeping
			// that apart from the target's socket makes such a reply visible.
			fallback := &recordingPacketConn{}
			writer.conn = fallback
			mb := make(buf.MultiBuffer, 0, 3)
			for range 3 {
				reply := buf.New()
				reply.WriteString("reply")
				test.set(reply)
				mb = append(mb, reply)
			}
			if err := writer.WriteMultiBuffer(mb); err != nil {
				t.Fatal(err)
			}
			if target.writes != 3 || fallback.writes != 0 || len(writer.conns) != 1 {
				t.Fatalf("target socket got %d of 3 replies, fallback %d; writer holds %d sockets, want 1", target.writes, fallback.writes, len(writer.conns))
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if !target.closed {
				t.Fatal("Close left the target socket open")
			}
		})
	}
}

// A writer whose own destination is not an IP still closes its socket.
func TestPacketWriterClosesUnkeyedSocket(t *testing.T) {
	target := &recordingPacketConn{}
	destination := net.UDPDestination(net.DomainAddress("example.com"), 443)
	writer := NewPacketWriter(target, &destination, 0, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 9}).(*PacketWriter)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !target.closed {
		t.Fatal("Close left the socket of a non-IP destination open")
	}
}
