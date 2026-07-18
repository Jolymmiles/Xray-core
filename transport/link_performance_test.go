package transport

import "testing"

var linkBenchmarkSink *Link

func BenchmarkConnectionLinkLifecycle(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		link := NewPooledLink(nil, nil)
		linkBenchmarkSink = link
		ReleasePooledLink(link)
	}
}
