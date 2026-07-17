package inbound

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

var firstBufferBenchmarkSink *buf.Buffer

func BenchmarkFirstBufferAllocation(b *testing.B) {
	b.Run("current-unmanaged", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			first := buf.FromBytes(make([]byte, buf.Size))
			first.Clear()
			firstBufferBenchmarkSink = first
		}
	})

	b.Run("pooled-production", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			first := buf.New()
			first.Clear()
			firstBufferBenchmarkSink = first
			first.Release()
		}
	})
}
