package net

import (
	stdnet "net"
	"net/netip"
	"testing"
)

var destinationStringBenchmarkSink string
var destinationPairBenchmarkSink [2]string
var destinationBenchmarkSink Destination
var destinationBytesBenchmarkSink []byte

func TestDestinationFromAddrPreservesBuiltinAddresses(t *testing.T) {
	tests := []struct {
		name string
		addr stdnet.Addr
		want string
	}{
		{name: "tcp-ipv4", addr: &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.1"), Port: 443}, want: "tcp:192.0.2.1:443"},
		{name: "tcp-ipv6", addr: &stdnet.TCPAddr{IP: stdnet.ParseIP("2001:db8::1"), Port: 443}, want: "tcp:[2001:db8::1]:443"},
		{name: "udp-ipv4", addr: &stdnet.UDPAddr{IP: stdnet.ParseIP("198.51.100.2"), Port: 53}, want: "udp:198.51.100.2:53"},
		{name: "unix", addr: &stdnet.UnixAddr{Name: "/tmp/xray.sock", Net: "unix"}, want: "unix:/tmp/xray.sock"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DestinationFromAddr(test.addr).String(); got != test.want {
				t.Fatalf("DestinationFromAddr(%v).String() = %q, want %q", test.addr, got, test.want)
			}
		})
	}
}

func TestTCPConnectionAddressesOwnEndpoints(t *testing.T) {
	source := &stdnet.TCPAddr{IP: stdnet.IP{192, 0, 2, 1}, Port: 12345}
	local := &stdnet.TCPAddr{IP: stdnet.ParseIP("2001:db8::1"), Port: 443}
	addresses := AcquireTCPConnectionAddresses(source, local)
	if addresses == nil {
		t.Fatal("AcquireTCPConnectionAddresses returned nil")
	}
	defer addresses.Release()
	source.IP[0] = 198
	local.IP[len(local.IP)-1] = 2
	if got := addresses.Source().String(); got != "tcp:192.0.2.1:12345" {
		t.Fatalf("source = %q", got)
	}
	if got := addresses.Local().String(); got != "tcp:[2001:db8::1]:443" {
		t.Fatalf("local = %q", got)
	}
}

func TestTCPConnectionAddressesAddressForms(t *testing.T) {
	tests := []struct {
		name string
		ip   stdnet.IP
		zone string
		want string
		ok   bool
	}{
		{name: "four-byte-ipv4", ip: stdnet.IP{192, 0, 2, 1}, want: "tcp:192.0.2.1:12345", ok: true},
		{name: "mapped-ipv4", ip: stdnet.ParseIP("192.0.2.1"), want: "tcp:192.0.2.1:12345", ok: true},
		{name: "ipv6", ip: stdnet.ParseIP("2001:db8::1"), want: "tcp:[2001:db8::1]:12345", ok: true},
		{name: "zoned-ipv6", ip: stdnet.ParseIP("fe80::1"), zone: "en0", ok: false},
		{name: "empty", ok: false},
		{name: "invalid-length", ip: stdnet.IP{1, 2, 3, 4, 5}, ok: false},
	}
	local := &stdnet.TCPAddr{IP: stdnet.IP{127, 0, 0, 1}, Port: 443}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addresses := AcquireTCPConnectionAddresses(&stdnet.TCPAddr{IP: test.ip, Port: 12345, Zone: test.zone}, local)
			if (addresses != nil) != test.ok {
				t.Fatalf("AcquireTCPConnectionAddresses() success = %t, want %t", addresses != nil, test.ok)
			}
			if addresses == nil {
				return
			}
			defer addresses.Release()
			if got := addresses.Source().String(); got != test.want {
				t.Fatalf("source = %q, want %q", got, test.want)
			}
		})
	}
}

func BenchmarkTCPConnectionAddressesLifecycle(b *testing.B) {
	source := &stdnet.TCPAddr{IP: stdnet.IP{192, 0, 2, 1}, Port: 12345}
	local := &stdnet.TCPAddr{IP: stdnet.IP{127, 0, 0, 1}, Port: 443}
	b.ReportAllocs()
	for b.Loop() {
		addresses := AcquireTCPConnectionAddresses(source, local)
		destinationBenchmarkSink = addresses.Source()
		addresses.Release()
	}
}

func TestDestinationFromAddrAllowsEmptyTCPIP(t *testing.T) {
	destination := DestinationFromAddr(&stdnet.TCPAddr{Port: 443})
	if destination.Network != Network_TCP || destination.Address != nil || destination.Port != 443 {
		t.Fatalf("DestinationFromAddr(empty TCP IP) = %#v", destination)
	}
}

func TestDestinationFromAddrAllowsEmptyUDPIP(t *testing.T) {
	destination := DestinationFromAddr(&stdnet.UDPAddr{Port: 53})
	if destination.Network != Network_UDP || destination.Address != nil || destination.Port != 53 {
		t.Fatalf("DestinationFromAddr(empty UDP IP) = %#v", destination)
	}
}

func BenchmarkDestinationFromTCPAddrIPv4(b *testing.B) {
	addr := &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.1"), Port: 443}
	b.ReportAllocs()
	for b.Loop() {
		destinationBenchmarkSink = DestinationFromAddr(addr)
	}
}

func BenchmarkDestinationFromUDPAddrIPv4(b *testing.B) {
	addr := &stdnet.UDPAddr{IP: stdnet.ParseIP("192.0.2.1"), Port: 443}
	b.ReportAllocs()
	for b.Loop() {
		destinationBenchmarkSink = DestinationFromAddr(addr)
	}
}

func TestAppendPortCoversUint16Range(t *testing.T) {
	for _, port := range []Port{0, 9, 10, 99, 100, 999, 1000, 9999, 10000, 65535} {
		if got := string(appendPort(nil, port)); got != port.String() {
			t.Fatalf("appendPort(%d) = %q, want %q", port, got, port.String())
		}
	}
}

func TestAppendIPv4PortPreservesAllOctets(t *testing.T) {
	for value := range 256 {
		ip := [4]byte{byte(value), byte(255 - value), byte(value), byte(255 - value)}
		got := string(AppendIPv4Port(nil, ip, 65535))
		want := netip.AddrPortFrom(netip.AddrFrom4(ip), 65535).String()
		if got != want {
			t.Fatalf("AppendIPv4Port(%v, 65535) = %q, want %q", ip, got, want)
		}
	}
}

func BenchmarkAppendIPv4Port(b *testing.B) {
	var storage [32]byte
	ip := [4]byte{192, 0, 2, 1}
	b.ReportAllocs()
	for b.Loop() {
		destinationBytesBenchmarkSink = AppendIPv4Port(storage[:0], ip, 443)
	}
}

func BenchmarkIPv4AddressString(b *testing.B) {
	address := IPv4Address([4]byte{192, 0, 2, 1})
	b.ReportAllocs()
	for b.Loop() {
		destinationStringBenchmarkSink = address.String()
	}
}

func BenchmarkDestinationNetAddrIPv4(b *testing.B) {
	destination := TCPDestination(IPv4Address([4]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		destinationStringBenchmarkSink = destination.NetAddr()
	}
}

func BenchmarkDestinationStringIPv4(b *testing.B) {
	destination := TCPDestination(IPv4Address([4]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		destinationStringBenchmarkSink = destination.String()
	}
}

func BenchmarkDestinationStringDomain(b *testing.B) {
	destination := TCPDestination(DomainAddress("example.com"), 443)
	b.ReportAllocs()
	for b.Loop() {
		destinationStringBenchmarkSink = destination.String()
	}
}

func TestDestinationNetAddrIPv4AllocationBudget(t *testing.T) {
	destination := TCPDestination(IPv4Address([4]byte{192, 0, 2, 1}), 443)
	allocations := testing.AllocsPerRun(1000, func() {
		destinationStringBenchmarkSink = destination.NetAddr()
	})
	if allocations > 1 {
		t.Fatalf("Destination.NetAddr() allocations = %.0f, want at most 1", allocations)
	}
}

func TestDestinationStringAllocationBudget(t *testing.T) {
	destinations := []Destination{
		TCPDestination(IPv4Address([4]byte{192, 0, 2, 1}), 443),
		TCPDestination(DomainAddress("example.com"), 443),
	}
	for _, destination := range destinations {
		allocations := testing.AllocsPerRun(1000, func() {
			destinationStringBenchmarkSink = destination.String()
		})
		if allocations > 1 {
			t.Fatalf("Destination.String() allocations = %.0f, want at most 1", allocations)
		}
	}
}

func TestFormatAccessEndpointsMatchesSeparateFormatting(t *testing.T) {
	tests := []struct {
		name   string
		source Destination
		target Destination
	}{
		{
			name:   "tcp-ipv4-to-domain",
			source: TCPDestination(IPv4Address([4]byte{192, 0, 2, 1}), 12345),
			target: TCPDestination(DomainAddress("example.com"), 443),
		},
		{
			name:   "udp-ipv6-to-ipv4",
			source: UDPDestination(IPv6Address([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 5353),
			target: UDPDestination(IPv4Address([4]byte{198, 51, 100, 2}), 53),
		},
		{
			name:   "unix",
			source: UnixDestination(DomainAddress("/tmp/source.sock")),
			target: UnixDestination(DomainAddress("/tmp/target.sock")),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			from, to := FormatAccessEndpoints(test.source, test.target)
			if from != test.source.NetAddr() || to != test.target.String() {
				t.Fatalf("FormatAccessEndpoints() = (%q, %q), want (%q, %q)", from, to, test.source.NetAddr(), test.target.String())
			}
		})
	}
}

func TestFormatAccessEndpointsFromAddrMatchesDestinationFormatting(t *testing.T) {
	target := TCPDestination(DomainAddress("example.com"), 443)
	for _, source := range []stdnet.Addr{
		&stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.1"), Port: 12345},
		&stdnet.TCPAddr{IP: stdnet.ParseIP("2001:db8::1"), Port: 12345, Zone: "ignored"},
		&stdnet.UDPAddr{IP: stdnet.ParseIP("198.51.100.2"), Port: 5353},
		&stdnet.UnixAddr{Name: "/tmp/source.sock", Net: "unix"},
	} {
		from, to := FormatAccessEndpointsFromAddr(source, target)
		wantFrom, wantTo := FormatAccessEndpoints(DestinationFromAddr(source), target)
		if from != wantFrom || to != wantTo {
			t.Fatalf("FormatAccessEndpointsFromAddr(%v) = (%q, %q), want (%q, %q)", source, from, to, wantFrom, wantTo)
		}
	}
}

func BenchmarkFormatAccessEndpoints(b *testing.B) {
	source := TCPDestination(IPv4Address([4]byte{192, 0, 2, 1}), 12345)
	target := TCPDestination(DomainAddress("example.com"), 443)
	b.ReportAllocs()
	for b.Loop() {
		from, to := FormatAccessEndpoints(source, target)
		destinationPairBenchmarkSink = [2]string{from, to}
	}
}

func BenchmarkFormatAccessEndpointsPooledConnectionSource(b *testing.B) {
	addresses := AcquireTCPConnectionAddresses(
		&stdnet.TCPAddr{IP: stdnet.IP{192, 0, 2, 1}, Port: 12345},
		&stdnet.TCPAddr{IP: stdnet.IP{127, 0, 0, 1}, Port: 443},
	)
	defer addresses.Release()
	source := addresses.Source()
	target := TCPDestination(DomainAddress("example.com"), 443)
	b.ReportAllocs()
	for b.Loop() {
		from, to := FormatAccessEndpoints(source, target)
		destinationPairBenchmarkSink = [2]string{from, to}
	}
}

func BenchmarkFormatAccessEndpointsIPv6(b *testing.B) {
	source := TCPDestination(IPv6Address(netip.MustParseAddr("2001:db8::1").As16()), 12345)
	target := TCPDestination(DomainAddress("example.com"), 443)
	b.ReportAllocs()
	for b.Loop() {
		from, to := FormatAccessEndpoints(source, target)
		destinationPairBenchmarkSink = [2]string{from, to}
	}
}

func BenchmarkFormatAccessEndpointsPooledConnectionSourceIPv6(b *testing.B) {
	addresses := AcquireTCPConnectionAddresses(
		&stdnet.TCPAddr{IP: stdnet.ParseIP("2001:db8::1"), Port: 12345},
		&stdnet.TCPAddr{IP: stdnet.ParseIP("2001:db8::2"), Port: 443},
	)
	defer addresses.Release()
	source := addresses.Source()
	target := TCPDestination(DomainAddress("example.com"), 443)
	b.ReportAllocs()
	for b.Loop() {
		from, to := FormatAccessEndpoints(source, target)
		destinationPairBenchmarkSink = [2]string{from, to}
	}
}

func BenchmarkFormatAccessEndpointsSeparate(b *testing.B) {
	source := TCPDestination(IPv4Address([4]byte{192, 0, 2, 1}), 12345)
	target := TCPDestination(DomainAddress("example.com"), 443)
	b.ReportAllocs()
	for b.Loop() {
		destinationPairBenchmarkSink = [2]string{source.NetAddr(), target.String()}
	}
}

func BenchmarkFormatAccessEndpointsFromTCPAddrBaseline(b *testing.B) {
	source := &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.1"), Port: 12345}
	target := TCPDestination(DomainAddress("example.com"), 443)
	b.ReportAllocs()
	for b.Loop() {
		from, to := FormatAccessEndpoints(DestinationFromAddr(source), target)
		destinationPairBenchmarkSink = [2]string{from, to}
	}
}

func BenchmarkFormatAccessEndpointsFromTCPAddr(b *testing.B) {
	source := &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.1"), Port: 12345}
	target := TCPDestination(DomainAddress("example.com"), 443)
	b.ReportAllocs()
	for b.Loop() {
		from, to := FormatAccessEndpointsFromAddr(source, target)
		destinationPairBenchmarkSink = [2]string{from, to}
	}
}
