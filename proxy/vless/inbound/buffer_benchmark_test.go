package inbound

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

var firstBufferBenchmarkSink *buf.Buffer

// TestManagedFirstBufferAllocationBudget pins the first-buffer lifecycle at one
// allocation: the Buffer header. The 8K storage and the inline packet metadata
// still come from the pool, which is what the budget is protecting.
//
// The header used to live inside the pooled slab, making this lifecycle
// allocation-free. That is not recoverable safely: a pooled header is handed
// back out by the next New(), so a stale holder releasing twice frees a live
// buffer (FORK_DEFECTS_REVIEW item C, reproduced on the first iteration by
// buf.TestStaleReleaseDoesNotFreeLiveSlabBuffer). Stale and live holders are
// one pointer, so no flag or generation inside Release() can separate them, and
// a header that is never reissued cannot be pooled. Anything above one here
// means the storage stopped being pooled — that is the regression to catch.
func TestManagedFirstBufferAllocationBudget(t *testing.T) {
	allocations := testing.AllocsPerRun(1000, func() {
		first := buf.New()
		firstBufferBenchmarkSink = first
		first.Release()
	})
	if allocations > 1 {
		t.Fatalf("managed first-buffer lifecycle allocations = %.0f, want at most 1 (header only)", allocations)
	}
}

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
