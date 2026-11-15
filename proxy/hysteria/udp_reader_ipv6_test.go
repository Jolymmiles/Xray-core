package hysteria

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// udpReaderIPv6Addresses are IPv6 literals parsed from the message bytes,
// including an IPv4-mapped one written in hexadecimal.
var udpReaderIPv6Addresses = []string{
	"[2001:db8::1]:443",
	"[::ffff:c000:201]:53",
	"[2001:db8:85a3::8a2e:370:7334]:51413",
}

// udpReaderAllocations returns the allocations of reading one more packet to
// a repeated address through ReadMultiBuffer and through readFromPacket.
func udpReaderAllocations(t *testing.T, address string) (multiBuffer, packet float64) {
	t.Helper()
	wire := hysteriaUDPWire(address, make([]byte, 1100))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	multiBuffer = testing.AllocsPerRun(1000, func() {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		buf.ReleaseMulti(mb)
	})
	payload := make([]byte, 2048)
	packet = testing.AllocsPerRun(1000, func() {
		if _, _, _, err := reader.readFromPacket(payload); err != nil {
			t.Fatal(err)
		}
	})
	return multiBuffer, packet
}

// A packet to an IPv6 literal allocates no more than a packet to an IPv4
// literal; both are parsed from the message bytes, and the allocation left in
// ReadMultiBuffer is the packet's buffer.
func TestUDPReaderIPv6AllocationBudget(t *testing.T) {
	ipv4MultiBuffer, ipv4Packet := udpReaderAllocations(t, "127.0.0.1:443")
	for _, address := range udpReaderIPv6Addresses {
		t.Run(address, func(t *testing.T) {
			multiBuffer, packet := udpReaderAllocations(t, address)
			if multiBuffer > ipv4MultiBuffer {
				t.Errorf("ReadMultiBuffer allocations for a repeated %s = %.0f, want at most %.0f as for IPv4", address, multiBuffer, ipv4MultiBuffer)
			}
			if packet > ipv4Packet {
				t.Errorf("readFromPacket allocations for a repeated %s = %.0f, want at most %.0f as for IPv4", address, packet, ipv4Packet)
			}
		})
	}
}

func TestUDPReaderDestinationsTrackAddressAndPort(t *testing.T) {
	addresses := []string{
		"[2001:db8::1]:443",
		"[2001:db8::2]:443",
		"[2001:db8::1]:53",
		"[2001:db8::1]:443",
		"127.0.0.1:443",
		"[2001:db8::1]:443",
		"Example.COM:443",
		"[2001:db8::1]:443",
	}
	want := make([]net.Destination, len(addresses))
	messages := make([][]byte, len(addresses))
	for index, address := range addresses {
		destination, err := parseUDPDestination(address)
		if err != nil {
			t.Fatal(err)
		}
		want[index] = destination
		messages[index] = hysteriaUDPWire(address, []byte("payload"))
	}

	// Packet metadata lives in the packet's slab, so it is checked before the
	// packet is released.
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: messages}}
	for index := range addresses {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if len(mb) != 1 || mb[0].UDP == nil {
			buf.ReleaseMulti(mb)
			t.Fatalf("packet metadata = %v, want one packet with a destination", mb)
		}
		got := *mb[0].UDP
		if got.NetAddr() != want[index].NetAddr() || got.Network != net.Network_UDP {
			buf.ReleaseMulti(mb)
			t.Fatalf("ReadMultiBuffer destination %d = %v, want %v", index, got, want[index])
		}
		buf.ReleaseMulti(mb)
	}

	reader = &UDPReader{reader: &sequentialDatagramReader{messages: messages}}
	payload := make([]byte, 64)
	for index := range addresses {
		_, destination, err := reader.ReadFrom(payload)
		if err != nil {
			t.Fatal(err)
		}
		if destination.NetAddr() != want[index].NetAddr() || destination.Network != net.Network_UDP {
			t.Fatalf("ReadFrom destination %d = %v, want %v", index, destination, want[index])
		}
	}
}

func TestUDPReaderSkipsMalformedIPv6Address(t *testing.T) {
	messages := [][]byte{
		hysteriaUDPWire("[2001:db8::1]:443", []byte("first")),
		hysteriaUDPWire("[2001:db8::1]:99999", []byte("bad port")),
		hysteriaUDPWire("[2001:db8::2]:443", []byte("second")),
	}
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: messages}}
	for _, want := range []string{"first", "second"} {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if got := mb.String(); got != want {
			buf.ReleaseMulti(mb)
			t.Fatalf("payload = %q, want %q", got, want)
		}
		buf.ReleaseMulti(mb)
	}
}

func benchmarkUDPReaderReadMultiBuffer(b *testing.B, address string) {
	wire := hysteriaUDPWire(address, make([]byte, 1100))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			b.Fatal(err)
		}
		udpMultiBufferSink = mb
		buf.ReleaseMulti(mb)
	}
}

func BenchmarkUDPReaderReadMultiBufferIPv6(b *testing.B) {
	benchmarkUDPReaderReadMultiBuffer(b, "[2001:db8::1]:443")
}

func BenchmarkUDPReaderReadMultiBufferIPv6Small(b *testing.B) {
	wire := hysteriaUDPWire("[2001:db8::1]:443", make([]byte, 64))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			b.Fatal(err)
		}
		udpMultiBufferSink = mb
		buf.ReleaseMulti(mb)
	}
}

func BenchmarkUDPReaderReadFromIPv6(b *testing.B) {
	wire := hysteriaUDPWire("[2001:db8::1]:443", make([]byte, 1100))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	payload := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		n, destination, err := reader.ReadFrom(payload)
		if err != nil {
			b.Fatal(err)
		}
		if n != 1100 {
			b.Fatalf("payload length = %d, want 1100", n)
		}
		udpDestinationSink = destination
	}
}

// cyclingDatagramReader returns its messages in turn, forever.
type cyclingDatagramReader struct {
	messages [][]byte
	index    int
}

func (r *cyclingDatagramReader) Read(payload []byte) (int, error) {
	message := r.messages[r.index]
	r.index++
	if r.index == len(r.messages) {
		r.index = 0
	}
	return copy(payload, message), nil
}

// udpReaderIPv6Targets are IPv6 destinations one UDP session might send to in
// turn, such as a full-cone socket talking to several peers.
var udpReaderIPv6Targets = []string{
	"[2001:db8:85a3::8a2e:370:7334]:443",
	"[2a00:1450:4001:82f::200e]:443",
	"[2606:4700:4700::1111]:53",
	"[2001:db8::1]:3478",
	"[2a03:2880:f12f:83:face:b00c:0:25de]:443",
	"[2001:db8:1234:5678::9]:51413",
	"[2620:fe::fe]:53",
	"[2001:db8:ffff::42]:6881",
}

// BenchmarkUDPReaderReadMultiBufferIPv6Alternating reads packets that cycle
// through n IPv6 destinations of one session, so each packet's address differs
// from the previous one unless n is 1.
func BenchmarkUDPReaderReadMultiBufferIPv6Alternating(b *testing.B) {
	for _, n := range []int{1, 2, 3, 4, 8} {
		b.Run(fmt.Sprintf("targets=%d", n), func(b *testing.B) {
			messages := make([][]byte, n)
			for index := range messages {
				messages[index] = hysteriaUDPWire(udpReaderIPv6Targets[index], make([]byte, 64))
			}
			reader := &UDPReader{reader: &cyclingDatagramReader{messages: messages}}
			b.ReportAllocs()
			for b.Loop() {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					b.Fatal(err)
				}
				udpMultiBufferSink = mb
				buf.ReleaseMulti(mb)
			}
		})
	}
}

// manyIPv6Targets returns n distinct IPv6 UDP addresses, like those of a DHT
// socket talking to many peers.
func manyIPv6Targets(n int) []string {
	targets := make([]string, n)
	for index := range targets {
		targets[index] = fmt.Sprintf("[2001:db8:%x::%x]:%d", index, index*7+1, 6881+index)
	}
	return targets
}

// Cycling through many IPv6 targets allocates no more per packet than a packet
// to an IPv4 literal: IPv6 literals are parsed from the message bytes, as IPv4
// literals are, whatever the previous packet's address was.
func TestUDPReaderManyIPv6TargetsAllocationBudget(t *testing.T) {
	ipv4MultiBuffer, ipv4Packet := udpReaderAllocations(t, "127.0.0.1:443")
	targets := manyIPv6Targets(16)
	messages := make([][]byte, len(targets))
	for index, target := range targets {
		messages[index] = hysteriaUDPWire(target, make([]byte, 64))
	}

	reader := &UDPReader{reader: &cyclingDatagramReader{messages: messages}}
	multiBuffer := testing.AllocsPerRun(1000, func() {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		buf.ReleaseMulti(mb)
	})
	if multiBuffer > ipv4MultiBuffer {
		t.Errorf("ReadMultiBuffer allocations cycling through %d IPv6 targets = %.0f, want at most %.0f as for IPv4", len(targets), multiBuffer, ipv4MultiBuffer)
	}

	reader = &UDPReader{reader: &cyclingDatagramReader{messages: messages}}
	payload := make([]byte, 2048)
	packet := testing.AllocsPerRun(1000, func() {
		if _, _, _, err := reader.readFromPacket(payload); err != nil {
			t.Fatal(err)
		}
	})
	if packet > ipv4Packet {
		t.Errorf("readFromPacket allocations cycling through %d IPv6 targets = %.0f, want at most %.0f as for IPv4", len(targets), packet, ipv4Packet)
	}
}

// Every IPv6 target of a cycle reaches the packet and its routing destination
// with the address and port the slow parser gives, including IPv4-mapped
// addresses written in hexadecimal, which become IPv4 destinations.
func TestUDPReaderIPv6DestinationsMatchSlowParser(t *testing.T) {
	addresses := append(manyIPv6Targets(6),
		"[::ffff:c000:201]:53",
		"[::FFFF:C000:0201]:53",
		"[2001:DB8::1]:443",
		"[::]:0",
		"[::1]:65535",
		"[1:2:3:4:5:6:7:8]:1",
		"[1::]:00080",
	)
	messages := make([][]byte, len(addresses))
	for index, address := range addresses {
		messages[index] = hysteriaUDPWire(address, []byte("payload"))
	}
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: messages}}
	for _, address := range addresses {
		want, err := parseUDPDestination(address)
		if err != nil {
			t.Fatal(err)
		}
		packet, packetDestination, err := reader.readBufferPacket()
		if err != nil {
			t.Fatal(err)
		}
		if packet.UDP == nil || packet.UDP.NetAddr() != want.NetAddr() || packet.UDP.Address.Family() != want.Address.Family() {
			packet.Release()
			t.Fatalf("%s: packet destination = %v, want %v", address, packet.UDP, want)
		}
		routing := packetDestination.Destination()
		packet.Release()
		if routing.NetAddr() != want.NetAddr() || routing.Address.Family() != want.Address.Family() || routing.Network != net.Network_UDP {
			t.Fatalf("%s: routing destination = %v, want %v", address, routing, want)
		}
	}
}

// The routing destination of an IPv6 packet must not alias the packet's
// pooled metadata, which the next packet overwrites.
func TestUDPReaderIPv6RoutingDestinationOutlivesPacketMetadata(t *testing.T) {
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: [][]byte{
		hysteriaUDPWire("[2001:db8::1]:443", []byte("first")),
		hysteriaUDPWire("[2001:db8::2]:53", []byte("second")),
	}}}
	first, firstDestination, err := reader.readBufferPacket()
	if err != nil {
		t.Fatal(err)
	}
	routing := firstDestination.Destination()
	first.Release()
	second, _, err := reader.readBufferPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	if got := routing.NetAddr(); got != "[2001:db8::1]:443" {
		t.Fatalf("routing destination changed with pooled packet metadata: %q", got)
	}
}

// FuzzParseIPv6UDPAddressMatchesSlowParser checks that whenever the fast IPv6
// parser accepts an address, the slow parser gives the same destination, and
// that the fast parser accepts every IPv6 address netip prints in hexadecimal.
func FuzzParseIPv6UDPAddressMatchesSlowParser(f *testing.F) {
	for _, seed := range []string{
		"[2001:db8::1]:443", "[::]:0", "[::1]:65535", "[1:2:3:4:5:6:7:8]:1",
		"[::ffff:c000:201]:53", "[::ffff:192.0.2.1]:53", "[fe80::1%eth0]:53",
		"[1::2::3]:1", "[1:2:3:4:5:6:7:8:9]:1", "[12345::]:1", "[::]:65536",
		"[::]:", "[::]", "::1:53", "[::1]:+53", "[g::]:1", "[1:2:3:4:5:6:7::]:1",
		"[::1:2:3:4:5:6:7]:1", "[1:2:3:4::5:6:7:8]:1", "[:1::]:1", "[1::]:1:",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, address []byte) {
		ip, port, ok := parseIPv6UDPAddress(address)
		if !ok {
			return
		}
		want, err := parseUDPDestination(string(address))
		if err != nil {
			t.Fatalf("fast parser accepted %q, slow parser failed: %v", address, err)
		}
		got := netip.AddrPortFrom(netip.AddrFrom16(ip).Unmap(), uint16(port))
		wantIP, wantIsIP := net.AddressToNetIPAddr(want.Address)
		if !wantIsIP || netip.AddrPortFrom(wantIP.Unmap(), uint16(want.Port)) != got {
			t.Fatalf("fast parser gave %s for %q, slow parser %v", got, address, want)
		}
	})
}

func TestParseIPv6UDPAddressAcceptsEveryHexForm(t *testing.T) {
	for _, raw := range [][16]byte{
		{},
		{15: 1},
		{0x20, 0x01, 0x0d, 0xb8, 15: 1},
		{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0},
	} {
		address := fmt.Sprintf("[%s]:%d", netip.AddrFrom16(raw), 443)
		ip, port, ok := parseIPv6UDPAddress([]byte(address))
		if !ok || ip != raw || port != 443 {
			t.Fatalf("parseIPv6UDPAddress(%q) = %x, %d, %v", address, ip, port, ok)
		}
	}
	for _, address := range []string{
		"[::ffff:192.0.2.1]:53", // dotted IPv4 tail: left to the slow parser
		"[fe80::1%eth0]:53",     // zone: the slow parser makes it a domain
		"[1::2::3]:1", "[1:2:3:4:5:6:7:8:9]:1", "[1:2:3:4::5:6:7:8]:1",
		"[12345::]:1", "[g::]:1", "[:1::]:1", "[1::]:", "[1::]", "[1::]:65536",
		"[1::]:+1", "[1::]:1:", "1::1:53", "[]:53",
	} {
		if _, _, ok := parseIPv6UDPAddress([]byte(address)); ok {
			t.Fatalf("parseIPv6UDPAddress accepted %q", address)
		}
	}
}

// ipv6Spellings writes ip in the hexadecimal spellings RFC 4291 allows: the
// canonical RFC 5952 form netip prints, all eight groups with and without
// leading zeros, upper case, and "::" in place of every run of zero groups,
// not only the longest one.
func ipv6Spellings(ip [16]byte) []string {
	var groups [8]uint16
	for index := range groups {
		groups[index] = uint16(ip[2*index])<<8 | uint16(ip[2*index+1])
	}
	join := func(format string, from, to int) string {
		parts := make([]string, 0, 8)
		for _, group := range groups[from:to] {
			parts = append(parts, fmt.Sprintf(format, group))
		}
		return strings.Join(parts, ":")
	}
	spellings := []string{
		netip.AddrFrom16(ip).WithZone("").StringExpanded(),
		join("%x", 0, 8),
		join("%04x", 0, 8),
		join("%04X", 0, 8),
		strings.ToUpper(join("%x", 0, 8)),
	}
	if !netip.AddrFrom16(ip).Is4In6() {
		spellings = append(spellings, netip.AddrFrom16(ip).String())
	}
	for start := 0; start < 8; start++ {
		if groups[start] != 0 {
			continue
		}
		for end := start + 1; end <= 8 && groups[end-1] == 0; end++ {
			spellings = append(spellings,
				join("%x", 0, start)+"::"+join("%x", end, 8),
				join("%04X", 0, start)+"::"+join("%04X", end, 8))
		}
	}
	return spellings
}

// Every hexadecimal spelling of an IPv6 address takes the fast path and gives
// the slow parser's destination; only the spellings it leaves alone (a dotted
// IPv4 tail, a zone) fall back to parseUDPDestination.
func TestParseIPv6UDPAddressAcceptsEverySpelling(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	addresses := [][16]byte{{}, {15: 1}, {10: 0xff, 11: 0xff, 12: 192, 14: 2, 15: 1}}
	for range 4000 {
		var ip [16]byte
		for index := range ip {
			// Mostly zero bytes, so zero groups and runs of them are common.
			if random.IntN(3) == 0 {
				ip[index] = byte(random.Uint32())
			}
		}
		addresses = append(addresses, ip)
	}
	for _, ip := range addresses {
		for _, spelling := range ipv6Spellings(ip) {
			port := net.Port(random.IntN(65536))
			address := fmt.Sprintf("[%s]:%d", spelling, port)
			gotIP, gotPort, ok := parseIPv6UDPAddress([]byte(address))
			if !ok || gotIP != ip || gotPort != port {
				t.Fatalf("parseIPv6UDPAddress(%q) = %x, %d, %v; want %x, %d", address, gotIP, gotPort, ok, ip, port)
			}
			want, err := parseUDPDestination(address)
			if err != nil {
				t.Fatalf("slow parser rejected %q: %v", address, err)
			}
			wantIP, _ := net.AddressToNetIPAddr(want.Address)
			if wantIP.Unmap() != netip.AddrFrom16(ip).Unmap() || want.Port != port {
				t.Fatalf("slow parser gave %v for %q", want, address)
			}
		}
	}
}

func BenchmarkUDPReaderReadMultiBufferManyIPv6(b *testing.B) {
	targets := manyIPv6Targets(16)
	messages := make([][]byte, len(targets))
	for index, target := range targets {
		messages[index] = hysteriaUDPWire(target, make([]byte, 64))
	}
	reader := &UDPReader{reader: &cyclingDatagramReader{messages: messages}}
	b.ReportAllocs()
	for b.Loop() {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			b.Fatal(err)
		}
		udpMultiBufferSink = mb
		buf.ReleaseMulti(mb)
	}
}

type oneShotMultiBufferReader struct{ mb buf.MultiBuffer }

func (r *oneShotMultiBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return r.mb, nil }

// When sniffing replaces a UDP target with a domain, the outbound handler
// wraps the link in EndpointOverrideReader with the session's routing address
// as the original. Packets the reader stores in buffer-owned address types
// must still be recognized and get the sniffed domain.
func TestUDPReaderPacketsFollowSniffedTargetOverride(t *testing.T) {
	for _, address := range []string{"[2001:db8::1]:443", "192.0.2.1:443", "Example.COM:443"} {
		t.Run(address, func(t *testing.T) {
			reader := &UDPReader{reader: repeatedDatagramReader(hysteriaUDPWire(address, []byte("quic")))}
			packet, packetDestination, err := reader.readBufferPacket()
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			override := &buf.EndpointOverrideReader{
				Reader:       &oneShotMultiBufferReader{buf.MultiBuffer{packet}},
				Dest:         net.DomainAddress("sniffed.example"),
				OriginalDest: packetDestination.Destination().Address,
			}
			mb, err := override.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			if got := mb[0].UDP; got.NetAddr() != "sniffed.example:443" {
				t.Fatalf("packet destination = %v (%T), want sniffed.example:443", got, got.Address)
			}
		})
	}
}

// A packet from a Hysteria inbound whose target sniffing replaced, sent on
// through a Hysteria outbound, must carry the sniffed target on the wire:
// UDPWriter reads the packet's inline address fast paths first.
func TestUDPWriterSendsSniffedTargetOverride(t *testing.T) {
	for _, address := range []string{"192.0.2.1:443", "[2001:db8::1]:443", "Example.COM:443"} {
		t.Run(address, func(t *testing.T) {
			reader := &UDPReader{reader: repeatedDatagramReader(hysteriaUDPWire(address, []byte("quic")))}
			packet, packetDestination, err := reader.readBufferPacket()
			if err != nil {
				t.Fatal(err)
			}
			override := &buf.EndpointOverrideReader{
				Reader:       &oneShotMultiBufferReader{buf.MultiBuffer{packet}},
				Dest:         net.DomainAddress("sniffed.example"),
				OriginalDest: packetDestination.Destination().Address,
			}
			mb, err := override.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			writer := &UDPWriter{writer: &wire, addr: "fallback.example:443"}
			if err := writer.WriteMultiBuffer(mb); err != nil {
				t.Fatal(err)
			}
			message, err := ParseUDPMessage(wire.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if message.Addr != "sniffed.example:443" {
				t.Fatalf("outbound wire address = %q, want sniffed.example:443", message.Addr)
			}
		})
	}
}
