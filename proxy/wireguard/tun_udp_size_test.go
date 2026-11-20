package wireguard

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// replyHandler takes the first datagram of a UDP connection from the device
// and writes replies back to it at once, as the inbound writes what its
// outbound hands it, then reports what the write returned.
type replyHandler struct {
	replies [][]byte
	written chan error
}

func (h replyHandler) HandleConnection(conn net.Conn, _ net.Destination) {
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 2048)); err != nil {
		h.written <- err
		return
	}
	mb := make(buf.MultiBuffer, len(h.replies))
	for i, payload := range h.replies {
		mb[i] = buf.NewWithSize(int32(len(payload)))
		mb[i].Write(payload)
	}
	h.written <- conn.(buf.Writer).WriteMultiBuffer(mb)
}

// udpPacket is a UDP packet from src to dst with the payload and right
// checksums, as a peer sends it through the tunnel.
func udpPacket(src, dst netip.AddrPort, payload []byte) []byte {
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp, src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)+len(payload)))
	udp = append(udp, payload...)
	var ip, addresses []byte
	if src.Addr().Is4() {
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(udp)))
		ip[8], ip[9] = 64, 17
		copy(ip[12:], src.Addr().AsSlice())
		copy(ip[16:], dst.Addr().AsSlice())
		binary.BigEndian.PutUint16(ip[10:], ^onesSum(ip, 0))
		addresses = ip[12:20]
	} else {
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(udp)))
		ip[6], ip[7] = 17, 64
		copy(ip[8:], src.Addr().AsSlice())
		copy(ip[24:], dst.Addr().AsSlice())
		addresses = ip[8:40]
	}
	check := ^onesSum(udp, uint32(onesSum(addresses, uint32(len(udp))+17)))
	if check == 0 {
		check = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], check)
	return append(ip, udp...)
}

// The outbounds hand the WireGuard and MASQUE inbounds a UDP reply whole, up
// to the 65535 bytes their framings allow, but an IP packet holds at most
// 65507 bytes of UDP payload over IPv4 and 65527 over IPv6. The inbounds write
// replies through the stack of their device, which refused a longer one with
// an error that ended the session. The inbound drops that reply and writes
// the next, which leaves the device as the packet after the one before it.
func TestUDPConnDropsRepliesTooLongForIP(t *testing.T) {
	for _, family := range []struct {
		name           string
		client, server netip.AddrPort
		longest        int
	}{
		{"IPv4", netip.MustParseAddrPort("10.66.0.2:1234"), netip.MustParseAddrPort("1.1.1.1:53"), 65507},
		{"IPv6", netip.MustParseAddrPort("[fd00::2]:1234"), netip.MustParseAddrPort("[2606:4700::1111]:53"), 65527},
	} {
		t.Run(family.name, func(t *testing.T) {
			sent := [][]byte{[]byte("ping"), bytes.Repeat([]byte{2}, family.longest+1), []byte("pong")}
			handler := replyHandler{replies: sent, written: make(chan error, 1)}
			dev, _, err := CreateNetTUN([]netip.Addr{
				netip.MustParseAddr("10.66.0.1"),
				netip.MustParseAddr("fd00::1"),
			}, nil, 1420, handler)
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

			if _, err := dev.Write([][]byte{udpPacket(family.client, family.server, []byte("query"))}, 0); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-handler.written:
				if err != nil {
					t.Fatalf("WriteMultiBuffer() = %v, want the long reply dropped", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the stack handed the inbound no connection for the query")
			}
			for _, want := range [][]byte{sent[0], sent[2]} {
				var p []byte
				select {
				case p = <-packets:
				case <-time.After(5 * time.Second):
					t.Fatalf("no packet with %q from the device", want)
				}
				header := 40
				ipLength := header + int(binary.BigEndian.Uint16(p[4:]))
				src := netip.AddrFrom16([16]byte(p[8:24]))
				dst := netip.AddrFrom16([16]byte(p[24:40]))
				if p[0]>>4 == 4 {
					header = int(p[0]&0xf) * 4
					ipLength = int(binary.BigEndian.Uint16(p[2:]))
					src = netip.AddrFrom4([4]byte(p[12:16]))
					dst = netip.AddrFrom4([4]byte(p[16:20]))
				}
				udp := p[header:]
				from := netip.AddrPortFrom(src, binary.BigEndian.Uint16(udp))
				to := netip.AddrPortFrom(dst, binary.BigEndian.Uint16(udp[2:]))
				if ipLength != len(p) || int(binary.BigEndian.Uint16(udp[4:])) != len(udp) || !bytes.Equal(udp[8:], want) {
					t.Fatalf("packet of %d bytes says IP length %d, UDP length %d, carries %d bytes; want %q", len(p), ipLength, binary.BigEndian.Uint16(udp[4:]), len(udp)-8, want)
				}
				if from != family.server || to != family.client {
					t.Fatalf("reply %v -> %v, want %v -> %v", from, to, family.server, family.client)
				}
			}
		})
	}
}
