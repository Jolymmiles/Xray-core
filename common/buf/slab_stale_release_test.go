package buf

import "testing"

// TestStaleReleaseDoesNotFreeLiveSlabBuffer is the regression test for
// FORK_DEFECTS_REVIEW item C.
//
// While the Buffer header lived inside the pooled managedBuffer, New() returned
// &slab.buffer, so New -> Release -> New handed the same *Buffer to a new owner.
// The stale holder's second Release() then wiped a live buffer and returned its
// slab to the pool while that owner still held it — silent cross-connection
// corruption, and it reproduced on the first iteration.
//
// The header is now heap-allocated, so a stale pointer can never equal a live
// one and the b.v == nil guard in Release() applies again. Re-embedding the
// header in the slab fails this test.
func TestStaleReleaseDoesNotFreeLiveSlabBuffer(t *testing.T) {
	const payload = "live-payload"

	// sync.Pool keeps a per-P private slot, so New -> Release -> New on one
	// goroutine usually recycles the same slab. Repeat to defeat scheduling luck.
	for i := range 64 {
		stale := New()
		stale.Release()

		live := New()
		if _, err := live.WriteString(payload); err != nil {
			t.Fatalf("iter %d: write: %v", i, err)
		}

		// The stale holder still has its pointer and releases it once more.
		stale.Release()

		if live.v == nil {
			t.Fatalf("iter %d: stale Release() wiped a live buffer", i)
		}
		if got := live.String(); got != payload {
			t.Fatalf("iter %d: live buffer content = %q, want %q", i, got, payload)
		}

		// The slab must not be back in the pool while `live` still owns it.
		other := New()
		if other == live {
			t.Fatalf("iter %d: pool handed a live *Buffer to a second owner", i)
		}
		if len(other.v) > 0 && len(live.v) > 0 && &other.v[0] == &live.v[0] {
			t.Fatalf("iter %d: pool handed live storage to a second owner", i)
		}

		other.Release()
		live.Release()
	}
}
