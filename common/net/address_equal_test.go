package net_test

import (
	stdnet "net"
	"testing"

	. "github.com/xtls/xray-core/common/net"
)

// customIPv6Address holds an IPv6 address in a type of its own, as packet
// buffers do, without a NetIPAddr method.
type customIPv6Address [16]byte

func (a *customIPv6Address) IP() stdnet.IP       { return stdnet.IP(a[:]) }
func (*customIPv6Address) Domain() string        { panic("not a domain") }
func (*customIPv6Address) Family() AddressFamily { return AddressFamilyIPv6 }
func (a *customIPv6Address) String() string      { return "[" + a.IP().String() + "]" }

func TestAddressEqual(t *testing.T) {
	ipv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	custom := customIPv6Address(ipv6)
	for _, test := range []struct {
		name string
		a, b Address
		want bool
	}{
		{name: "same IPv4", a: IPv4Address([4]byte{192, 0, 2, 1}), b: ParseAddress("192.0.2.1"), want: true},
		{name: "different IPv4", a: IPv4Address([4]byte{192, 0, 2, 1}), b: ParseAddress("192.0.2.2")},
		{name: "same IPv6", a: IPv6Address(ipv6), b: ParseAddress("2001:db8::1"), want: true},
		{name: "IPv6 in its own type", a: &custom, b: IPv6Address(ipv6), want: true},
		{name: "different IPv6 in its own type", a: &custom, b: ParseAddress("2001:db8::2")},
		{name: "same domain", a: DomainAddress("example.com"), b: DomainAddress("example.com"), want: true},
		{name: "different domain", a: DomainAddress("example.com"), b: DomainAddress("example.org")},
		{name: "IPv4 against IPv6", a: ParseAddress("192.0.2.1"), b: ParseAddress("2001:db8::1")},
		{name: "domain against IP", a: DomainAddress("192.0.2.1"), b: ParseAddress("192.0.2.1")},
		{name: "nil", a: nil, b: ParseAddress("192.0.2.1")},
		{name: "both nil", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := AddressEqual(test.a, test.b); got != test.want {
				t.Fatalf("AddressEqual(%v, %v) = %v, want %v", test.a, test.b, got, test.want)
			}
			if got := AddressEqual(test.b, test.a); got != test.want {
				t.Fatalf("AddressEqual(%v, %v) = %v, want %v", test.b, test.a, got, test.want)
			}
		})
	}
}
