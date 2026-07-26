package encoding

import (
	"net/netip"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// TestDecodedAddressOutlivesRequest pins the ownership rule for decoded VLESS
// request addresses: the destination escapes into session.Outbound, routing
// rules and the asynchronous access log, so it must keep its own storage for
// as long as anything holds the net.Address. Handing out a view of memory that
// a later connection can overwrite corrupts unrelated sessions.
func TestDecodedAddressOutlivesRequest(t *testing.T) {
	t.Run("domain", func(t *testing.T) {
		first := newDomainRequest([]byte("example.com"))
		retained := first.Address

		// Whatever the decoder does with the finished request, a retained
		// address must not observe it.
		for range 64 {
			next := newDomainRequest([]byte("attacker.invalid"))
			_ = next.Address.Domain()
		}

		if got := retained.Domain(); got != "example.com" {
			t.Errorf("Domain() = %q after later requests, want %q", got, "example.com")
		}
		if got := retained.String(); got != "example.com" {
			t.Errorf("String() = %q after later requests, want %q", got, "example.com")
		}
	})

	t.Run("long domain", func(t *testing.T) {
		long := make([]byte, 0, 200)
		for len(long) < 200 {
			long = append(long, "abcdefghij."...)
		}
		long = long[:200]

		first := newDomainRequest(long)
		retained := first.Address

		for range 64 {
			_ = newDomainRequest([]byte("attacker.invalid"))
		}

		if got := retained.Domain(); got != string(long) {
			t.Errorf("Domain() = %q after later requests, want the original long domain", got)
		}
	})

	t.Run("ipv4", func(t *testing.T) {
		first := newIPv4Request([]byte{192, 0, 2, 1})
		retained := first.Address

		for range 64 {
			_ = newIPv4Request([]byte{198, 51, 100, 9})
		}

		if got := retained.IP().String(); got != "192.0.2.1" {
			t.Errorf("IP() = %q after later requests, want %q", got, "192.0.2.1")
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		original := netip.MustParseAddr("2001:db8::1").As16()
		other := netip.MustParseAddr("2001:db8::dead").As16()

		first := newIPv6Request(original[:])
		retained := first.Address

		for range 64 {
			_ = newIPv6Request(other[:])
		}

		if got := retained.IP().String(); got != "2001:db8::1" {
			t.Errorf("IP() = %q after later requests, want %q", got, "2001:db8::1")
		}
	})
}

// TestDecodedAddressIPSliceIsNotAliased guards the second half of the same
// rule: net.Address.IP() returns a slice, and callers such as the router keep
// it. It must not alias storage the decoder can rewrite.
func TestDecodedAddressIPSliceIsNotAliased(t *testing.T) {
	request := newIPv4Request([]byte{192, 0, 2, 1})
	retained := request.Address.IP()

	other := newIPv4Request([]byte{198, 51, 100, 9})
	_ = other

	if got := net.IP(retained).String(); got != "192.0.2.1" {
		t.Errorf("retained IP slice = %q, want %q", got, "192.0.2.1")
	}
}
