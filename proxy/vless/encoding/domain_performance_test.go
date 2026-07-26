package encoding

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestDecodedRequestHeaderCarriesNoPriorProtocolState(t *testing.T) {
	request := newDomainRequest([]byte("example.com"))
	request.Option = 0xff
	request.Security = protocol.SecurityType_AES128_GCM
	request.User = new(protocol.MemoryUser)
	ReleaseRequestHeader(request)

	request = newDomainRequest([]byte("example.org"))
	defer ReleaseRequestHeader(request)
	if request.Option != 0 || request.Security != 0 || request.User != nil {
		t.Fatalf("decoded request retained protocol state: %+v", request)
	}
}

func TestIsPlainDomainByteSet(t *testing.T) {
	for value := 0; value < 256; value++ {
		c := byte(value)
		want := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '.' || c == '_'
		if got := isPlainDomain(string([]byte{c})); got != want {
			t.Fatalf("isPlainDomain(%d) = %v, want %v", value, got, want)
		}
	}
}

func TestIsPlainDomainAllTailLengths(t *testing.T) {
	for length := 0; length <= 32; length++ {
		domain := make([]byte, length)
		for i := range domain {
			domain[i] = 'a'
		}
		if !isPlainDomain(string(domain)) {
			t.Fatalf("valid domain of length %d rejected", length)
		}
		for invalid := range domain {
			domain[invalid] = '/'
			if isPlainDomain(string(domain)) {
				t.Fatalf("invalid byte at %d accepted for length %d", invalid, length)
			}
			domain[invalid] = 'a'
		}
	}
}

func BenchmarkIsPlainDomain(b *testing.B) {
	domain := "cdn-api.example-service.com"
	b.ReportAllocs()
	for b.Loop() {
		if !isPlainDomain(domain) {
			b.Fatal("benchmark domain rejected")
		}
	}
}
