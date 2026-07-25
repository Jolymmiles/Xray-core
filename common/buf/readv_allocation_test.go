//go:build !wasm && !openbsd && !race

package buf

import "testing"

func TestAllocStrategyReusesVectorStorage(t *testing.T) {
	strategy := allocStrategy{current: 8}
	warm := strategy.Alloc()
	ReleaseMulti(warm)

	allocations := testing.AllocsPerRun(1000, func() {
		buffers := strategy.Alloc()
		ReleaseMulti(buffers)
	})
	if allocations != 0 {
		t.Fatalf("allocStrategy.Alloc made %.2f allocations per call, want 0", allocations)
	}
}
