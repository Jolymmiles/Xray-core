package buf

import "testing"

func TestStaleReleaseDoesNotFreeLiveSlabBuffer(t *testing.T) {
	const payload = "live-payload"

	for i := range 64 {
		stale := New()
		stale.Release()

		live := New()
		if _, err := live.WriteString(payload); err != nil {
			t.Fatalf("iter %d: write: %v", i, err)
		}

		stale.Release()
		if live.v == nil {
			t.Fatalf("iter %d: stale Release() wiped a live buffer", i)
		}
		if got := live.String(); got != payload {
			t.Fatalf("iter %d: live buffer content = %q, want %q", i, got, payload)
		}

		other := New()
		if len(other.v) > 0 && len(live.v) > 0 && &other.v[0] == &live.v[0] {
			t.Fatalf("iter %d: pool handed live storage to a second owner", i)
		}

		other.Release()
		live.Release()
	}
}
