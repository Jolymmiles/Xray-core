package encoding

import (
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

// recycledDomainRequest reproduces the pooling this package used to do, so the
// cost of giving decoded addresses their own lifetime is measured rather than
// asserted. It is deliberately test-only: recycling a request whose address has
// escaped is the bug TestDecodedAddressOutlivesRequest pins.
type recycledDomainRequest struct {
	header  protocol.RequestHeader
	address recycledDomainAddress
}

type recycledDomainAddress struct {
	inlineDomainAddress
	owner *recycledDomainRequest
}

var recycledDomainPool sync.Pool

func newRecycledDomainRequest(domain []byte) *protocol.RequestHeader {
	request, _ := recycledDomainPool.Get().(*recycledDomainRequest)
	if request == nil {
		request = new(recycledDomainRequest)
		request.address.owner = request
	}
	address := &request.address
	if len(domain) <= len(address.bytes) {
		address.length = byte(copy(address.bytes[:], domain))
		address.long = ""
	} else {
		address.length = 0
		address.long = string(domain)
	}
	request.header.Address = address
	return &request.header
}

func releaseRecycledDomainRequest(request *protocol.RequestHeader) {
	address, ok := request.Address.(*recycledDomainAddress)
	if !ok {
		return
	}
	owner := address.owner
	owner.header = protocol.RequestHeader{}
	recycledDomainPool.Put(owner)
}

func BenchmarkDecodedDomainRequest(b *testing.B) {
	cases := []struct {
		name   string
		domain []byte
	}{
		{"short", []byte("example.com")},
		{"inline_max", []byte("aaaaaaaaaa.bbbbbbbbbb.cccccccccc.dddddddddd.eeeeeeeeee.ffffffff")},
		{"overflow", []byte("aaaaaaaaaa.bbbbbbbbbb.cccccccccc.dddddddddd.eeeeeeeeee.ffffffffff.gggg")},
	}

	for _, tc := range cases {
		if tc.name == "inline_max" && len(tc.domain) != inlineDomainCapacity {
			b.Fatalf("inline_max domain is %d bytes, want %d", len(tc.domain), inlineDomainCapacity)
		}

		b.Run(tc.name+"/owned", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				request := newDomainRequest(tc.domain)
				if request.Address.Domain() == "" {
					b.Fatal("empty domain")
				}
			}
		})

		b.Run(tc.name+"/recycled", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				request := newRecycledDomainRequest(tc.domain)
				if request.Address.Domain() == "" {
					b.Fatal("empty domain")
				}
				releaseRecycledDomainRequest(request)
			}
		})
	}
}

func BenchmarkDecodedIPRequest(b *testing.B) {
	ipv4 := []byte{192, 0, 2, 1}
	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	b.Run("ipv4", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			request := newIPv4Request(ipv4)
			if request.Address == nil {
				b.Fatal("nil address")
			}
		}
	})

	b.Run("ipv6", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			request := newIPv6Request(ipv6)
			if request.Address == nil {
				b.Fatal("nil address")
			}
		}
	})
}
