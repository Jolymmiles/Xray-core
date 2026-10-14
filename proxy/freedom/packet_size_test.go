package freedom

import (
	"bytes"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// The inbounds hand freedom a UDP datagram whole, up to the 65535 bytes their
// framings allow, but an IP packet holds at most 65507 bytes of UDP payload
// over IPv4 and 65527 over IPv6. The socket refused a longer datagram, and
// the error ended the UDP session. Freedom drops such a datagram, as the
// proxy writers drop one they cannot frame, and sends the next whole.
func TestPacketWriterDropsDatagramsTooLongForIP(t *testing.T) {
	for _, family := range []struct {
		name    string
		ip      net.IP
		longest int
	}{
		{"IPv4", net.LocalHostIP.IP(), 65507},
		{"IPv6", net.LocalHostIPv6.IP(), 65527},
	} {
		t.Run(family.name, func(t *testing.T) {
			receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: family.ip})
			if err != nil {
				t.Skipf("no %s loopback: %v", family.name, err)
			}
			t.Cleanup(func() { receiver.Close() })
			destination := net.DestinationFromAddr(receiver.LocalAddr())

			unconnected, err := net.ListenUDP("udp", &net.UDPAddr{IP: family.ip})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { unconnected.Close() })
			connected, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { connected.Close() })

			for name, conn := range map[string]net.Conn{
				"packet conn":    &net.PacketConnWrapper{PacketConn: unconnected, Dest: receiver.LocalAddr()},
				"connected conn": connected,
			} {
				t.Run(name, func(t *testing.T) {
					sent := [][]byte{
						bytes.Repeat([]byte{1}, family.longest+1),
						bytes.Repeat([]byte{2}, family.longest),
						[]byte("ping"),
					}
					mb := make(buf.MultiBuffer, len(sent))
					for i, payload := range sent {
						mb[i] = buf.NewWithSize(int32(len(payload)))
						mb[i].Write(payload)
						udp := destination
						mb[i].UDP = &udp
					}
					writer := NewPacketWriter(conn, &Handler{}, nil, net.Destination{}, destination, nil)
					if err := writer.WriteMultiBuffer(mb); err != nil {
						t.Fatalf("WriteMultiBuffer() = %v, want the long datagram dropped", err)
					}
					received := make([]byte, 65536)
					for _, payload := range sent[1:] {
						if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
							t.Fatal(err)
						}
						n, _, err := receiver.ReadFrom(received)
						if err != nil {
							t.Fatalf("waiting for the datagram of %d bytes: %v", len(payload), err)
						}
						if !bytes.Equal(received[:n], payload) {
							t.Fatalf("received a datagram of %d bytes, want the one of %d", n, len(payload))
						}
					}
				})
			}
		})
	}
}
