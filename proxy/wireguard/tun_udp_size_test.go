package wireguard

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// The outbounds hand the WireGuard and MASQUE inbounds a UDP reply whole, up
// to the 65535 bytes their framings allow, but an IP packet holds at most
// 65507 bytes of UDP payload over IPv4 and 65527 over IPv6. The 16-bit lengths
// of a longer one wrapped, and the stack took a malformed packet. The inbound
// drops that reply and writes the next.
func TestUDPConnDropsRepliesTooLongForIP(t *testing.T) {
	for _, family := range []struct {
		name     string
		src, dst net.Destination
		longest  int
	}{
		{"IPv4", net.UDPDestination(net.ParseAddress("10.66.0.2"), 1234), net.UDPDestination(net.ParseAddress("1.1.1.1"), 53), 65507},
		{"IPv6", net.UDPDestination(net.ParseAddress("fd00::2"), 1234), net.UDPDestination(net.ParseAddress("2606:4700::1111"), 53), 65527},
	} {
		t.Run(family.name, func(t *testing.T) {
			dev, _, gstack, err := CreateNetTUN([]netip.Addr{
				netip.MustParseAddr("10.66.0.1"),
				netip.MustParseAddr("fd00::1"),
			}, nil, 1420, false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { dev.Close() })
			packets := make(chan []byte, 4)
			go func() {
				for {
					p := make([]byte, 70000)
					sizes := make([]int, 1)
					if _, err := dev.Read([][]byte{p}, sizes, 0); err != nil {
						return
					}
					packets <- p[:sizes[0]]
				}
			}()

			m := &udpManager{stack: gstack}
			c := &udpConn{writeFunc: m.writeRawUDPPacket, src: family.src, dst: family.dst}
			sent := [][]byte{[]byte("ping"), bytes.Repeat([]byte{2}, family.longest+1), []byte("pong")}
			mb := make(buf.MultiBuffer, len(sent))
			for i, payload := range sent {
				mb[i] = buf.NewWithSize(int32(len(payload)))
				mb[i].Write(payload)
			}
			if err := c.WriteMultiBuffer(mb); err != nil {
				t.Fatalf("WriteMultiBuffer() = %v, want the long reply dropped", err)
			}
			for _, want := range [][]byte{sent[0], sent[2]} {
				var p []byte
				select {
				case p = <-packets:
				case <-time.After(5 * time.Second):
					t.Fatalf("no packet with %q from the stack", want)
				}
				var udp header.UDP
				if p[0]>>4 == 4 {
					ip := header.IPv4(p)
					if !ip.IsValid(len(p)) || int(ip.TotalLength()) != len(p) {
						t.Fatalf("IPv4 packet of %d bytes says %d", len(p), ip.TotalLength())
					}
					udp = header.UDP(ip.Payload())
				} else {
					ip := header.IPv6(p)
					if !ip.IsValid(len(p)) || int(ip.PayloadLength())+header.IPv6MinimumSize != len(p) {
						t.Fatalf("IPv6 packet of %d bytes says a payload of %d", len(p), ip.PayloadLength())
					}
					udp = header.UDP(ip.Payload())
				}
				if int(udp.Length()) != len(udp) || !bytes.Equal(udp.Payload(), want) {
					t.Fatalf("UDP packet of %d bytes says %d, carries %d bytes; want %q", len(udp), udp.Length(), len(udp.Payload()), want)
				}
			}
		})
	}
}
