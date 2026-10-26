package splithttp

import (
	"testing"
	"time"
)

// TestFlowRebase steps the path's round trip from 20 to 120 ms under a
// kernel whose min_rtt stays at 20: with cuts that do not move the queue the
// queue is counted from 120 ms once flowBaseWindow has passed, a queue of
// the server's own on top of that does not raise it, and the path coming
// back drops it. With cuts that work, the same round trip stays a queue.
func TestFlowRebase(t *testing.T) {
	const kernel = 20 * time.Millisecond
	run := func(c *flowConn, now time.Time, rtt time.Duration, gain float64, d time.Duration) time.Time {
		for end := now.Add(d); now.Before(end); now = now.Add(flowKernelEvery) {
			c.effect.active, c.effect.gain, c.pinned = gain < 1, gain, true
			c.kstat = tcpStats{rtt: rtt, minRTT: kernel, rttVar: time.Millisecond}
			c.rebase(now)
		}
		return now
	}
	now := time.Unix(1, 0)

	c := &flowConn{}
	now = run(c, now, kernel, 1, time.Second)
	now = run(c, now, 120*time.Millisecond, 0, flowBaseWindow/2)
	if c.kstat.minRTT != kernel {
		t.Fatalf("rebased to %v before cuts had failed for %v", c.kstat.minRTT, flowBaseWindow)
	}
	now = run(c, now, 120*time.Millisecond, 0, 2*flowBaseWindow)
	if c.kstat.minRTT != 120*time.Millisecond {
		t.Fatalf("after the path moved to 120 ms the queue counts from %v", c.kstat.minRTT)
	}
	now = run(c, now, 140*time.Millisecond, 1, 3*flowBaseWindow)
	if c.kstat.minRTT != 120*time.Millisecond {
		t.Fatalf("a queue of the server's own raised the base to %v", c.kstat.minRTT)
	}
	run(c, now, kernel, 1, 2*flowBaseWindow)
	if c.kstat.minRTT != kernel || c.base != 0 {
		t.Fatalf("the path came back and the queue still counts from %v", c.kstat.minRTT)
	}

	c = &flowConn{}
	now = run(c, now, kernel, 1, time.Second)
	run(c, now, 120*time.Millisecond, 1, 3*flowBaseWindow)
	if c.kstat.minRTT != kernel {
		t.Fatalf("cuts that work, and the queue still counts from %v", c.kstat.minRTT)
	}
}

// TestFlowRebaseNotOwnQueue reads a low gain beside downloads whose caps are
// well above init: the queue is their data, a gain that reads low now and
// then on connections that share it, and the base stays the kernel's.
func TestFlowRebaseNotOwnQueue(t *testing.T) {
	c := &flowConn{}
	now := time.Unix(1, 0)
	for end := now.Add(3 * flowBaseWindow); now.Before(end); now = now.Add(flowKernelEvery) {
		c.effect.active, c.effect.gain, c.pinned = true, 0.1, false
		c.kstat = tcpStats{rtt: 110 * time.Millisecond, minRTT: 50 * time.Millisecond, rttVar: 100 * time.Microsecond}
		c.rebase(now)
	}
	if c.kstat.minRTT != 50*time.Millisecond {
		t.Fatalf("a queue of the server's own was taken for the path: the queue counts from %v", c.kstat.minRTT)
	}
}

// TestFlowRebaseKeepsBaseThroughJitter steps the path by 20 ms and then has
// the round trip's variance grow to 5 ms, a setpoint as large as the step:
// the base stays until the path comes back.
func TestFlowRebaseKeepsBaseThroughJitter(t *testing.T) {
	c := &flowConn{}
	now := time.Unix(1, 0)
	step := func(rtt, rttVar time.Duration, gain float64, d time.Duration) {
		for end := now.Add(d); now.Before(end); now = now.Add(flowKernelEvery) {
			c.effect.active, c.effect.gain, c.pinned = gain < 1, gain, true
			c.kstat = tcpStats{rtt: rtt, minRTT: 20 * time.Millisecond, rttVar: rttVar}
			c.rebase(now)
		}
	}
	step(40*time.Millisecond, time.Millisecond, 0, 2*flowBaseWindow)
	step(40*time.Millisecond, 5*time.Millisecond, 1, 2*flowBaseWindow)
	if c.kstat.minRTT != 40*time.Millisecond {
		t.Fatalf("jitter on the moved path dropped the base: the queue counts from %v", c.kstat.minRTT)
	}
	step(20*time.Millisecond, time.Millisecond, 1, 2*flowBaseWindow)
	if c.base != 0 {
		t.Fatalf("the path came back and the base stayed at %v", c.base)
	}
}

// TestFlowRebaseWhereGainFroze has the empty path's round trip step from 20
// to 120 ms under a download whose cap is above twice init, from the start
// window and from 512 KiB, while the kernel keeps its min_rtt at 20 ms. The
// first cut lands in flight and the queue, the path's own, does not move:
// the gain goes to none, the cuts stop and the cap stays above twice init.
// rebase waited for caps at init and never ran; the gain of none is now
// enough for it. Where the queue then keeps moving by two fifths, as a queue
// of the server's own does while the connections that share it cut and
// grow, with the cap still over twice init, it is not the path's, and
// rebase does not run.
func TestFlowRebaseWhereGainFroze(t *testing.T) {
	const oldMinRTT = 20 * time.Millisecond
	const newPathRTT = 120 * time.Millisecond
	for _, tc := range []struct {
		name   string
		rtt    func(since time.Duration) time.Duration
		caps   []int32
		rebase bool
	}{
		{"path moved", func(time.Duration) time.Duration { return newPathRTT }, []int32{flowStartWindow, 512 << 10}, true},
		// From 512 KiB the cap stays over twice init as it follows the round
		// trip: it is the queue that does not stand that tells this from a
		// path.
		{"queue moves", func(since time.Duration) time.Duration {
			if since < time.Second || since/(400*time.Millisecond)%2 == 0 {
				return newPathRTT
			}
			return 80 * time.Millisecond
		}, []int32{512 << 10}, false},
	} {
		for _, startCap := range tc.caps {
			h, s := queuedDownload(t)
			now := time.Unix(1000, 0)
			h.c.mu.Lock()
			h.c.incremental = true
			h.c.rttBase = oldMinRTT
			s.down.cap = startCap
			s.down.flat = flowFullRounds
			s.down.mark, s.down.markBase = now, s.down.returned
			s.down.qAt = now
			h.c.mu.Unlock()
			// A second at the old path's setpoint seeds the base window.
			for end := now.Add(time.Second); now.Before(end); now = now.Add(oldMinRTT) {
				h.c.mu.Lock()
				h.c.kstat = tcpStats{rtt: oldMinRTT + flowPIMinSet, minRTT: oldMinRTT, rttVar: time.Millisecond, inFlight: int64(s.down.cap)}
				h.c.rebase(now)
				s.down.returned += int64(s.down.cap)
				h.c.governDown(now, s)
				h.c.mu.Unlock()
			}
			// The round trip rises; the kernel's min_rtt stays. The download
			// is held by its cap, and the reader returns a cap per round trip.
			step := now
			for end := now.Add(3 * flowBaseWindow); now.Before(end); now = now.Add(oldMinRTT) {
				rtt := tc.rtt(now.Sub(step))
				h.c.mu.Lock()
				h.c.kstat = tcpStats{rtt: rtt, minRTT: oldMinRTT, rttVar: time.Millisecond, inFlight: int64(s.down.cap)}
				h.c.rebase(now)
				s.down.returned += int64(s.down.cap) * int64(oldMinRTT) / int64(rtt)
				h.c.governDown(now, s)
				h.c.mu.Unlock()
			}
			h.c.mu.Lock()
			base, cap, pinned, gain := h.c.base, s.down.cap, h.c.pinned, h.c.effect.gain
			h.c.mu.Unlock()
			if (base != 0) != tc.rebase {
				t.Fatalf("%s, cap %d: base %v (cap %d, pinned %v, gain %v), want a rebase: %v",
					tc.name, startCap, base, cap, pinned, gain, tc.rebase)
			}
		}
	}
}
