package buf

import (
	"net"
	"testing"

	"github.com/xtls/xray-core/common"
)

// TestPooledReaderReleaseAfterInterruptIsSafe is the production ordering after
// the mux ownership fix: worker finishes (Interrupts link) before signaling
// done; caller then Releases the pooled reader. No concurrent Interrupt after
// Release — that was the #5110 done-before-cleanup race, not a reader bug.
func TestPooledReaderReleaseAfterInterruptIsSafe(t *testing.T) {
	const iterations = 5000
	for i := 0; i < iterations; i++ {
		c1, c2 := net.Pipe()
		br := NewPooledBufferedReader(NewPooledReader(c1), nil)

		// finish() order: Interrupt link, then caller may Release.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("iter %d: panic: %v", i, r)
				}
			}()
			_ = common.Interrupt(br)
			br.Release()
		}()

		// Pool reuse must not trip on the released object via a live reference.
		x, y := net.Pipe()
		b2 := NewPooledBufferedReader(NewPooledReader(x), nil)
		b2.Release()
		_ = x.Close()
		_ = y.Close()
		_ = c1.Close()
		_ = c2.Close()
	}
}
