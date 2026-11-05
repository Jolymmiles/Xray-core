package splithttp

import (
	"testing"
	"time"
)

// TestFlowPIStepsUpAtShare has two downloads of one connection under the
// setpoint, one taking four times what the other does: at the connection's
// share both grow by the same bytes, where each growing by its own rate keeps
// the split. Over the setpoint each still shrinks by its own rate, as without
// a share.
func TestFlowPIStepsUpAtShare(t *testing.T) {
	ms := time.Millisecond
	now := time.Unix(1e6, 0)
	pi := func(cap int32, copied int64, rtt time.Duration, share float64) int32 {
		w := flowWindow{cap: cap, mark: now.Add(-110 * ms), returned: copied}
		w.pi(now, tcpStats{rtt: rtt, minRTT: 100 * ms}, h2InitWindow, 1<<30, 1, share)
		return w.cap - cap
	}
	share := (300e3 + 1200e3) / 2 / 0.11
	small, large := pi(1<<20, 300e3, 110*ms, share), pi(4<<20, 1200e3, 110*ms, share)
	if small <= 0 || small != large {
		t.Fatalf("under the setpoint at share %.0f B/s the downloads grew by %d and %d", share, small, large)
	}
	if own := pi(1<<20, 300e3, 110*ms, 0); own >= small {
		t.Fatalf("the smaller download grew by %d at its own rate, %d at the share", own, small)
	}
	for _, d := range []struct {
		cap    int32
		copied int64
	}{{1 << 20, 300e3}, {4 << 20, 1200e3}} {
		if got, want := pi(d.cap, d.copied, 160*ms, share), pi(d.cap, d.copied, 160*ms, 0); got != want || got >= 0 {
			t.Fatalf("over the setpoint a cap of %d moved by %d at the share, %d at its own rate", d.cap, got, want)
		}
	}
}
