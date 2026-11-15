package udp

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

var sourceSink net.Destination

// benchmarkSource runs handleInput's per-packet source step over packets whose
// addresses live in buffer slabs, cycling through targets.
func benchmarkSource(b *testing.B, targets int) {
	packets := make([]*buf.Buffer, targets)
	for index := range packets {
		packets[index] = buf.New()
		packets[index].SetManagedUDPIPv6([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(index + 1)}, 443)
	}
	defer buf.ReleaseMulti(packets)
	dest := ownedDestination(net.UDPDestination(net.LocalHostIPv6, 443))
	b.ReportAllocs()
	index := 0
	for b.Loop() {
		packet := packets[index]
		index = (index + 1) % targets
		if packet.UDP != nil && !sameUDPSource(dest, *packet.UDP) {
			dest = ownedDestination(*packet.UDP)
		}
		sourceSink = dest
	}
}

func BenchmarkDispatcherSourceSameIPv6(b *testing.B)        { benchmarkSource(b, 1) }
func BenchmarkDispatcherSourceAlternatingIPv6(b *testing.B) { benchmarkSource(b, 2) }

// BenchmarkDispatcherSourceCopy is the step as it was: a plain copy.
func BenchmarkDispatcherSourceCopy(b *testing.B) {
	packet := buf.New()
	defer packet.Release()
	packet.SetManagedUDPIPv6([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}, 443)
	var dest net.Destination
	b.ReportAllocs()
	for b.Loop() {
		if packet.UDP != nil {
			dest = *packet.UDP
		}
		sourceSink = dest
	}
}

// BenchmarkDispatcherSourceSamePlain covers outbounds such as freedom, which
// give each packet a fresh plain address value.
func BenchmarkDispatcherSourceSamePlain(b *testing.B) {
	packet := buf.New()
	defer packet.Release()
	dest := ownedDestination(net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53))
	b.ReportAllocs()
	for b.Loop() {
		packet.UDP = &net.Destination{Network: net.Network_UDP, Address: net.IPAddress([]byte{192, 0, 2, 1}), Port: 53}
		if packet.UDP != nil && !sameUDPSource(dest, *packet.UDP) {
			dest = ownedDestination(*packet.UDP)
		}
		sourceSink = dest
	}
}

// BenchmarkDispatcherSourceCopyPlain is the plain-address step as it was.
func BenchmarkDispatcherSourceCopyPlain(b *testing.B) {
	packet := buf.New()
	defer packet.Release()
	var dest net.Destination
	b.ReportAllocs()
	for b.Loop() {
		packet.UDP = &net.Destination{Network: net.Network_UDP, Address: net.IPAddress([]byte{192, 0, 2, 1}), Port: 53}
		if packet.UDP != nil {
			dest = *packet.UDP
		}
		sourceSink = dest
	}
}
