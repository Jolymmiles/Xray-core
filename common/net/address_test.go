package net_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/common/net"
)

func TestAddressToNetIPAddr(t *testing.T) {
	tests := []struct {
		name    string
		address Address
		want    netip.Addr
		valid   bool
	}{
		{"IPv4", IPv4Address([4]byte{192, 0, 2, 1}), netip.MustParseAddr("192.0.2.1"), true},
		{"IPv6", IPv6Address([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), netip.MustParseAddr("2001:db8::1"), true},
		{"domain", DomainAddress("example.com"), netip.Addr{}, false},
		{"nil", nil, netip.Addr{}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid := AddressToNetIPAddr(test.address)
			if got != test.want || valid != test.valid {
				t.Fatalf("AddressToNetIPAddr() = (%v, %v), want (%v, %v)", got, valid, test.want, test.valid)
			}
		})
	}
}

func TestAddressProperty(t *testing.T) {
	type addrProprty struct {
		IP     []byte
		Domain string
		Family AddressFamily
		String string
	}

	testCases := []struct {
		Input  Address
		Output addrProprty
	}{
		{
			Input: IPAddress([]byte{byte(1), byte(2), byte(3), byte(4)}),
			Output: addrProprty{
				IP:     []byte{byte(1), byte(2), byte(3), byte(4)},
				Family: AddressFamilyIPv4,
				String: "1.2.3.4",
			},
		},
		{
			Input: IPAddress([]byte{
				byte(1), byte(2), byte(3), byte(4),
				byte(1), byte(2), byte(3), byte(4),
				byte(1), byte(2), byte(3), byte(4),
				byte(1), byte(2), byte(3), byte(4),
			}),
			Output: addrProprty{
				IP: []byte{
					byte(1), byte(2), byte(3), byte(4),
					byte(1), byte(2), byte(3), byte(4),
					byte(1), byte(2), byte(3), byte(4),
					byte(1), byte(2), byte(3), byte(4),
				},
				Family: AddressFamilyIPv6,
				String: "[102:304:102:304:102:304:102:304]",
			},
		},
		{
			Input: IPAddress([]byte{
				byte(0), byte(0), byte(0), byte(0),
				byte(0), byte(0), byte(0), byte(0),
				byte(0), byte(0), byte(255), byte(255),
				byte(1), byte(2), byte(3), byte(4),
			}),
			Output: addrProprty{
				IP:     []byte{byte(1), byte(2), byte(3), byte(4)},
				Family: AddressFamilyIPv4,
				String: "1.2.3.4",
			},
		},
		{
			Input: DomainAddress("example.com"),
			Output: addrProprty{
				Domain: "example.com",
				Family: AddressFamilyDomain,
				String: "example.com",
			},
		},
		{
			Input: IPAddress(net.IPv4(1, 2, 3, 4)),
			Output: addrProprty{
				IP:     []byte{byte(1), byte(2), byte(3), byte(4)},
				Family: AddressFamilyIPv4,
				String: "1.2.3.4",
			},
		},
		{
			Input: ParseAddress("[2001:4860:0:2001::68]"),
			Output: addrProprty{
				IP:     []byte{0x20, 0x01, 0x48, 0x60, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68},
				Family: AddressFamilyIPv6,
				String: "[2001:4860:0:2001::68]",
			},
		},
		{
			Input: ParseAddress("::0"),
			Output: addrProprty{
				IP:     AnyIPv6.IP(),
				Family: AddressFamilyIPv6,
				String: "[::]",
			},
		},
		{
			Input: ParseAddress("[::ffff:123.151.71.143]"),
			Output: addrProprty{
				IP:     []byte{123, 151, 71, 143},
				Family: AddressFamilyIPv4,
				String: "123.151.71.143",
			},
		},
		{
			Input: NewIPOrDomain(ParseAddress("example.com")).AsAddress(),
			Output: addrProprty{
				Domain: "example.com",
				Family: AddressFamilyDomain,
				String: "example.com",
			},
		},
		{
			Input: NewIPOrDomain(ParseAddress("8.8.8.8")).AsAddress(),
			Output: addrProprty{
				IP:     []byte{8, 8, 8, 8},
				Family: AddressFamilyIPv4,
				String: "8.8.8.8",
			},
		},
		{
			Input: NewIPOrDomain(ParseAddress("[2001:4860:0:2001::68]")).AsAddress(),
			Output: addrProprty{
				IP:     []byte{0x20, 0x01, 0x48, 0x60, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68},
				Family: AddressFamilyIPv6,
				String: "[2001:4860:0:2001::68]",
			},
		},
	}

	for _, testCase := range testCases {
		actual := addrProprty{
			Family: testCase.Input.Family(),
			String: testCase.Input.String(),
		}
		if testCase.Input.Family().IsIP() {
			actual.IP = testCase.Input.IP()
		} else {
			actual.Domain = testCase.Input.Domain()
		}

		if r := cmp.Diff(actual, testCase.Output); r != "" {
			t.Error("for input: ", testCase.Input, ":", r)
		}
	}
}

func TestInvalidAddressConvertion(t *testing.T) {
	panics := func(f func()) (ret bool) {
		defer func() {
			if r := recover(); r != nil {
				ret = true
			}
		}()
		f()
		return false
	}

	testCases := []func(){
		func() { ParseAddress("8.8.8.8").Domain() },
		func() { ParseAddress("2001:4860:0:2001::68").Domain() },
		func() { ParseAddress("example.com").IP() },
	}
	for idx, testCase := range testCases {
		if !panics(testCase) {
			t.Error("case ", idx, " failed")
		}
	}
}

var parseAddressBenchmarkSink Address

func TestParseAddressAllocationBudgets(t *testing.T) {
	for _, test := range []struct {
		value string
		max   float64
	}{
		{value: "8.8.8.8", max: 1},
		{value: "2001:4860:0:2001::68", max: 1},
		{value: "example.com", max: 1},
	} {
		t.Run(test.value, func(t *testing.T) {
			allocations := testing.AllocsPerRun(1000, func() {
				parseAddressBenchmarkSink = ParseAddress(test.value)
			})
			if allocations > test.max {
				t.Fatalf("ParseAddress(%q) allocations = %.0f, want at most %.0f", test.value, allocations, test.max)
			}
		})
	}
}

func TestParseAddressHexLikeDomainAndIPv6(t *testing.T) {
	if family := ParseAddress("dead.beef").Family(); family != AddressFamilyDomain {
		t.Fatalf("dead.beef family = %v, want domain", family)
	}
	if family := ParseAddress("dead::beef").Family(); family != AddressFamilyIPv6 {
		t.Fatalf("dead::beef family = %v, want IPv6", family)
	}
}

func BenchmarkParseAddressIPv4(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		addr := ParseAddress("8.8.8.8")
		if addr.Family() != AddressFamilyIPv4 {
			panic("not ipv4")
		}
		parseAddressBenchmarkSink = addr
	}
}

func BenchmarkParseAddressIPv6(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		addr := ParseAddress("2001:4860:0:2001::68")
		if addr.Family() != AddressFamilyIPv6 {
			panic("not ipv6")
		}
		parseAddressBenchmarkSink = addr
	}
}

func BenchmarkParseAddressDomain(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		addr := ParseAddress("example.com")
		if addr.Family() != AddressFamilyDomain {
			panic("not domain")
		}
		parseAddressBenchmarkSink = addr
	}
}
