package transport

import "testing"

var linkBenchmarkSink *Link

// BenchmarkConnectionLinkAllocation measures what a dispatched connection
// actually pays for its Link pair. Pooling was removed because a Link escapes
// into the outbound handler for the whole connection lifetime, so recycling it
// cannot be proven safe, and this is the cost it would have saved: two tiny
// allocations against a connection that performs a TLS handshake.
func BenchmarkConnectionLinkAllocation(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		linkBenchmarkSink = &Link{}
	}
}
