package hysteria

import (
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
