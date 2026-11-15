package hysteria

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// Addresses that the IPv4 and known-domain fast paths of UDPReader do not
// take: they go through net.SplitHostPort and net.ParseAddress.
var udpReaderGeneralAddresses = []string{
	"[2001:db8::1]:443",
	"[::ffff:192.0.2.1]:53",
	"Example.COM:443",
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

// A packet to the same address as the previous one allocates no more than a
// packet to an IPv4 literal, whose address is parsed without allocating; the
// allocation left in ReadMultiBuffer is the packet's buffer.
func TestUDPReaderGeneralAddressAllocationBudget(t *testing.T) {
	ipv4MultiBuffer, ipv4Packet := udpReaderAllocations(t, "127.0.0.1:443")
	for _, address := range udpReaderGeneralAddresses {
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

func TestUDPReaderGeneralAddressCacheTracksAddressAndPort(t *testing.T) {
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

// A session that sends to several IPv6 peers in turn, up to the cache size,
// allocates no more per packet than one that sends to a single IPv4 address.
func TestUDPReaderAlternatingGeneralAddressAllocationBudget(t *testing.T) {
	ipv4MultiBuffer, _ := udpReaderAllocations(t, "127.0.0.1:443")
	for n := 2; n <= udpGeneralDestinationCacheSize; n++ {
		t.Run(fmt.Sprintf("targets=%d", n), func(t *testing.T) {
			messages := make([][]byte, n)
			for index := range messages {
				messages[index] = hysteriaUDPWire(udpReaderIPv6Targets[index], make([]byte, 64))
			}
			reader := &UDPReader{reader: &cyclingDatagramReader{messages: messages}}
			// AllocsPerRun's warm-up run reads only one packet, so the first
			// pass over the targets fills the cache here.
			for range messages {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				buf.ReleaseMulti(mb)
			}
			allocations := testing.AllocsPerRun(1000, func() {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				buf.ReleaseMulti(mb)
			})
			if allocations > ipv4MultiBuffer {
				t.Fatalf("ReadMultiBuffer allocations cycling through %d IPv6 targets = %.0f, want at most %.0f as for IPv4", n, allocations, ipv4MultiBuffer)
			}
		})
	}
}

// Cycling through more targets than the cache holds evicts entries; every
// packet must still carry its own destination.
func TestUDPReaderGeneralAddressCacheEviction(t *testing.T) {
	targets := udpReaderIPv6Targets[:udpGeneralDestinationCacheSize+2]
	var addresses []string
	for range 3 {
		addresses = append(addresses, targets...)
	}
	addresses = append(addresses, targets[len(targets)-1], targets[0], targets[len(targets)-1])
	messages := make([][]byte, len(addresses))
	for index, address := range addresses {
		messages[index] = hysteriaUDPWire(address, []byte("payload"))
	}
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: messages}}
	for index, address := range addresses {
		want, err := parseUDPDestination(address)
		if err != nil {
			t.Fatal(err)
		}
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if len(mb) != 1 || mb[0].UDP == nil || mb[0].UDP.NetAddr() != want.NetAddr() {
			buf.ReleaseMulti(mb)
			t.Fatalf("packet %d destination = %v, want %v", index, mb, want)
		}
		buf.ReleaseMulti(mb)
	}
}

func TestUDPReaderGeneralAddressCacheRejectsMalformedAddress(t *testing.T) {
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
