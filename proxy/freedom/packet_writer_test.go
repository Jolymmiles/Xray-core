package freedom

import (
	"bytes"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// The dispatcher's QUIC sniffer reads the buffers of a UDP link as the
// datagrams the destination receives. That holds because the outbound sends
// each buffer it is handed as a datagram of its own, whatever the sizes of the
// buffers and whether the socket is connected.
func TestPacketWriterSendsEachBufferAsADatagram(t *testing.T) {
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { receiver.Close() })
	sizes := []int{8192, 527, 1200, 9000}
	payloads := make([][]byte, len(sizes))
	for i, size := range sizes {
		payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, size)
	}
	destination := net.DestinationFromAddr(receiver.LocalAddr())

	unconnected, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
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
			writer := NewPacketWriter(conn, &Handler{}, nil, net.Destination{}, destination, nil)
			mb := make(buf.MultiBuffer, 0, len(payloads))
			for _, payload := range payloads {
				b := buf.NewWithSize(int32(len(payload)))
				b.Write(payload)
				udp := destination
				b.UDP = &udp
				mb = append(mb, b)
			}
			if err := writer.WriteMultiBuffer(mb); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, 65535)
			for i, payload := range payloads {
				if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				n, _, err := receiver.ReadFrom(received)
				if err != nil {
					t.Fatalf("datagram %d: %v", i, err)
				}
				if !bytes.Equal(received[:n], payload) {
					t.Fatalf("datagram %d holds %d bytes, want its buffer of %d bytes", i, n, len(payload))
				}
			}
		})
	}
}
