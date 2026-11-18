package buf_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type oneShotReader struct{ mb MultiBuffer }

func (r *oneShotReader) ReadMultiBuffer() (MultiBuffer, error) { return r.mb, nil }

type collectingWriter struct{ mb MultiBuffer }

func (w *collectingWriter) WriteMultiBuffer(mb MultiBuffer) error {
	w.mb = append(w.mb, mb...)
	return nil
}

// managedUDPPacket returns a packet whose destination lives in the buffer's
// own slab types, as the Hysteria UDP reader stores it.
func managedUDPPacket(t *testing.T, set func(*Buffer)) *Buffer {
	t.Helper()
	packet := New()
	t.Cleanup(packet.Release)
	set(packet)
	return packet
}

// Sniffing that replaces a UDP target installs EndpointOverrideReader and
// EndpointOverrideWriter. They must recognize a packet's address by value,
// whatever type holds it, or packets keep the original IP instead of the
// sniffed domain.
func TestEndpointOverrideMatchesManagedAddresses(t *testing.T) {
	ipv4 := [4]byte{192, 0, 2, 1}
	ipv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	sniffed := net.DomainAddress("example.com")
	for _, test := range []struct {
		name     string
		original net.Address
		set      func(*Buffer)
	}{
		{name: "ipv4", original: net.IPv4Address(ipv4), set: func(b *Buffer) { b.SetManagedUDPIPv4(ipv4, 443) }},
		{name: "ipv6", original: net.IPv6Address(ipv6), set: func(b *Buffer) { b.SetManagedUDPIPv6(ipv6, 443) }},
		{name: "ipv6-net", original: net.IPv6Address(ipv6), set: func(b *Buffer) {
			b.SetManagedUDPDestination(net.UDPDestination(net.IPv6Address(ipv6), 443))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := managedUDPPacket(t, test.set)
			reader := &EndpointOverrideReader{Reader: &oneShotReader{MultiBuffer{packet}}, Dest: sniffed, OriginalDest: test.original}
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			if got := mb[0].UDP; !got.Address.Family().IsDomain() || got.Address.Domain() != "example.com" || got.Port != 443 {
				t.Fatalf("read packet destination = %v (%T), want the sniffed example.com:443", got, got.Address)
			}
		})
	}

	t.Run("writer", func(t *testing.T) {
		packet := managedUDPPacket(t, func(b *Buffer) { b.SetManagedUDPDomain("example.com", 443) })
		sink := &collectingWriter{}
		writer := &EndpointOverrideWriter{Writer: sink, Dest: sniffed, OriginalDest: net.IPv6Address(ipv6)}
		if err := writer.WriteMultiBuffer(MultiBuffer{packet}); err != nil {
			t.Fatal(err)
		}
		if got := sink.mb[0].UDP; got.NetAddr() != "[2001:db8::1]:443" {
			t.Fatalf("written packet destination = %v (%T), want the original [2001:db8::1]:443", got, got.Address)
		}
	})
}

// A packet to another address keeps it.
func TestEndpointOverrideKeepsOtherAddresses(t *testing.T) {
	ipv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	other := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 2}
	for _, test := range []struct {
		name string
		set  func(*Buffer)
		want string
	}{
		{name: "other-ipv6", set: func(b *Buffer) { b.SetManagedUDPIPv6(other, 443) }, want: "[2001:db8::2]:443"},
		{name: "ipv4", set: func(b *Buffer) { b.SetManagedUDPIPv4([4]byte{192, 0, 2, 1}, 443) }, want: "192.0.2.1:443"},
		{name: "domain", set: func(b *Buffer) { b.SetManagedUDPDomain("other.example", 443) }, want: "other.example:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := managedUDPPacket(t, test.set)
			reader := &EndpointOverrideReader{Reader: &oneShotReader{MultiBuffer{packet}}, Dest: net.DomainAddress("example.com"), OriginalDest: net.IPv6Address(ipv6)}
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			if got := mb[0].UDP.NetAddr(); got != test.want {
				t.Fatalf("packet destination = %s, want %s", got, test.want)
			}
		})
	}
}
