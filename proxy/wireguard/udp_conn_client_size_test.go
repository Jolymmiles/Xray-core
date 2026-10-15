package wireguard

import (
	"bytes"
	"errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// The inbounds hand the WireGuard and MASQUE outbounds a UDP datagram whole,
// up to 65535 bytes, but an IP packet holds at most 65507 bytes of UDP
// payload over IPv4 and 65527 over IPv6. The tunnel's socket refused a longer
// one, and the error ended the UDP session. UDPConnClient drops it and sends
// the rest of the MultiBuffer; any other error still ends the session.
func TestUDPConnClientDropsDatagramsTooLongForIP(t *testing.T) {
	for _, family := range []struct {
		name    string
		ip      net.IP
		longest int
	}{
		{"IPv4", net.LocalHostIP.IP(), 65507},
		{"IPv6", net.LocalHostIPv6.IP(), 65527},
	} {
		t.Run(family.name, func(t *testing.T) {
			sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: family.ip})
			if err != nil {
				t.Skipf("no %s loopback: %v", family.name, err)
			}
			t.Cleanup(func() { sink.Close() })
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: family.ip})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })

			client := &UDPConnClient{PacketConn: conn, Dest: sink.LocalAddr().(*net.UDPAddr)}
			sent := [][]byte{[]byte("ping"), bytes.Repeat([]byte{2}, family.longest+1), []byte("pong")}
			mb := make(buf.MultiBuffer, len(sent))
			for i, payload := range sent {
				mb[i] = buf.NewWithSize(int32(len(payload)))
				mb[i].Write(payload)
			}
			if err := client.WriteMultiBuffer(mb); err != nil {
				t.Fatalf("WriteMultiBuffer() = %v, want the long datagram dropped", err)
			}
			received := make([]byte, 65536)
			for _, want := range [][]byte{sent[0], sent[2]} {
				if err := sink.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				n, _, err := sink.ReadFrom(received)
				if err != nil {
					t.Fatalf("waiting for %q: %v", want, err)
				}
				if !bytes.Equal(received[:n], want) {
					t.Fatalf("received a datagram of %d bytes, want %q", n, want)
				}
			}

			conn.Close()
			if err := client.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ping"))}); !errors.Is(err, stdnet.ErrClosed) {
				t.Fatalf("WriteMultiBuffer() = %v, want the error of the closed socket", err)
			}
		})
	}
}

// recordingPacketConn takes a datagram of any length, as a userspace stack
// may, and records the length of each.
type recordingPacketConn struct {
	net.PacketConn
	lengths []int
}

func (c *recordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.lengths = append(c.lengths, len(p))
	return len(p), nil
}

// The tunnel's stack may take a datagram that no IP packet holds, so the
// client drops it before the write rather than rely on the socket's refusal.
func TestUDPConnClientDropsDatagramsTooLongForIPBeforeTheWrite(t *testing.T) {
	for _, family := range []struct {
		dest    *net.UDPAddr
		longest int
	}{
		{&net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 53}, 65507},
		{&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53}, 65527},
	} {
		conn := &recordingPacketConn{}
		client := &UDPConnClient{PacketConn: conn, Dest: family.dest}
		mb := buf.MultiBuffer{buf.NewWithSize(int32(family.longest + 1)), buf.NewWithSize(int32(family.longest))}
		mb[0].Extend(int32(family.longest + 1))
		mb[1].Extend(int32(family.longest))
		if err := client.WriteMultiBuffer(mb); err != nil {
			t.Fatal(err)
		}
		if len(conn.lengths) != 1 || conn.lengths[0] != family.longest {
			t.Fatalf("to %v the stack took datagrams of %v bytes, want only the one of %d", family.dest, conn.lengths, family.longest)
		}
	}
}
