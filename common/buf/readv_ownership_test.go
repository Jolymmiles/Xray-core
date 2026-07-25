//go:build !wasm && !openbsd

package buf

import "testing"

func TestAllocStrategyPreservesOutstandingVector(t *testing.T) {
	strategy := allocStrategy{current: 2}
	first := strategy.Alloc()
	first[0].WriteByte(1)
	first[1].WriteByte(2)

	second := strategy.Alloc()
	defer ReleaseMulti(second)
	if got := first[0].Byte(0); got != 1 {
		t.Fatalf("first outstanding vector was overwritten: got %d, want 1", got)
	}
	if got := first[1].Byte(0); got != 2 {
		t.Fatalf("first outstanding vector was overwritten: got %d, want 2", got)
	}
	ReleaseMulti(first)
}
