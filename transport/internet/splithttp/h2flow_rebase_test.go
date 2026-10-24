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
