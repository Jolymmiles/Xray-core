package tun

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// The outbounds hand the TUN inbound a UDP reply whole, up to the 65535 bytes
// their framings allow, but an IP packet holds at most 65507 bytes of UDP
// payload over IPv4 and 65527 over IPv6. The 16-bit lengths of a longer one
// wrapped, and the TUN took a malformed packet. The inbound drops that reply
// and writes the next.
func TestUDPConnDropsRepliesTooLongForIP(t *testing.T) {
	for _, family := range []struct {
		name     string
		src, dst net.Destination
		header   int
		longest  int
	}{
		{"IPv4", net.UDPDestination(net.ParseAddress("10.0.0.1"), 1234), net.UDPDestination(net.ParseAddress("10.0.0.2"), 53), ipv4HeaderSize, 65507},
		{"IPv6", net.UDPDestination(net.ParseAddress("fd00::1"), 1234), net.UDPDestination(net.ParseAddress("fd00::2"), 53), ipv6HeaderSize, 65527},
	} {
		t.Run(family.name, func(t *testing.T) {
			l := newLink()
			var written [][]byte
			l.out = func(packet []byte) { written = append(written, packet) }
			s := &stack{tun: l}
			c := &udpConn{handler: &udpConnectionHandler{writePacket: s.writeUDP}, src: family.src, dst: family.dst}

			sent := [][]byte{[]byte("ping"), bytes.Repeat([]byte{2}, family.longest+1), bytes.Repeat([]byte{3}, family.longest)}
			mb := make(buf.MultiBuffer, len(sent))
			for i, payload := range sent {
				mb[i] = buf.NewWithSize(int32(len(payload)))
				mb[i].Write(payload)
			}
			if err := c.WriteMultiBuffer(mb); err != nil {
				t.Fatalf("WriteMultiBuffer() = %v, want the long reply dropped", err)
			}
			if len(written) != 2 {
				t.Fatalf("the TUN took %d packets, want 2", len(written))
			}
			for i, want := range [][]byte{sent[0], sent[2]} {
				p := written[i]
				ipLength := int(binary.BigEndian.Uint16(p[2:]))
				if family.header == ipv6HeaderSize {
					ipLength = family.header + int(binary.BigEndian.Uint16(p[4:]))
				}
				udpLength := int(binary.BigEndian.Uint16(p[family.header+4:]))
				if ipLength != len(p) || udpLength != len(p)-family.header || !bytes.Equal(p[family.header+udpHeaderSize:], want) {
					t.Fatalf("packet %d of %d bytes says IP length %d, UDP length %d; want the reply of %d bytes", i, len(p), ipLength, udpLength, len(want))
				}
			}
		})
	}
}
