package splithttp

import (
	"testing"
	"time"
)

// TestFlowGroupProbe runs a probe of a group whose connections carry a
// steady rate before it and, while their windows are wide, a quarter more:
// the path answered, so it has moved. Then one where the rate stays: a link
// the client fills, no answer, and no new probe until flowProbeQuiet.
func TestFlowGroupProbe(t *testing.T) {
	run := func(g *flowGroup, now time.Time, before, wide int64) (time.Time, time.Time) {
		g.peak = 4 * float64(before) // the rate fell, as when the path moved
		g.request(now, 100*time.Millisecond)
		for range 2 * 10 {
			is, _ := g.step(now)
			rate := before
			if is {
				rate = wide
			}
			g.bytes.Add(rate / 20)
			now = now.Add(50 * time.Millisecond)
		}
		_, moved := g.step(now)
		return now, moved
	}
	g := &flowGroup{key: "a"}
	now, moved := run(g, time.Unix(1, 0), 1e6, 1.25e6)
	if moved.IsZero() {
		t.Fatal("a quarter more over the probe read as no answer")
	}

	g = &flowGroup{key: "b"}
	now, moved = run(g, now, 1e6, 1e6)
	if !moved.IsZero() {
		t.Fatal("the same rate over the probe read as an answer")
	}
	g.request(now.Add(flowProbeQuiet/2), 100*time.Millisecond)
	if g.phase != flowProbeIdle {
		t.Fatalf("a probe started %v after one with no answer", flowProbeQuiet/2)
	}
}

// TestFlowGroupShared has two connections join the same server's group and a
// third another's; the group goes once the last of its connections does.
func TestFlowGroupShared(t *testing.T) {
	a, b, c := joinFlowGroup("s:1"), joinFlowGroup("s:1"), joinFlowGroup("s:2")
	if a != b || a == c {
		t.Fatal("connections to one server do not share a group, or to two servers do")
	}
	a.leave()
	if joinFlowGroup("s:1") != b {
		t.Fatal("the group went while a connection still used it")
	}
	b.leave()
	b.leave()
	c.leave()
	flowGroups.Lock()
	left := len(flowGroups.m)
	flowGroups.Unlock()
	if left != 0 {
		t.Fatalf("%d groups left after every connection went", left)
	}
}

// TestFlowGroupQuietGrows has probe after probe go unanswered: each waits
// twice as long as the one before, up to flowProbeQuietMost, and an answer
// brings the wait back.
func TestFlowGroupQuietGrows(t *testing.T) {
	g := &flowGroup{key: "q"}
	now := time.Unix(1, 0)
	var waits []time.Duration
	for range 6 {
		g.peak, g.cur = 1e6, 0
		g.request(now, 100*time.Millisecond)
		for g.phase != flowProbeIdle {
			now = now.Add(100 * time.Millisecond)
			g.bytes.Add(1000)
			g.step(now)
		}
		waits = append(waits, g.next.Sub(now))
		now = g.next
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits after unanswered probes %v, want %v", waits, want)
		}
	}
}

// TestFlowGroupNoProbeAtSteadyRate has a group carry the same every second, as
// a client that fills its link does: no connection's request starts a probe.
// Once the rate falls to a quarter, one does.
func TestFlowGroupNoProbeAtSteadyRate(t *testing.T) {
	g := &flowGroup{key: "steady"}
	now := time.Unix(1, 0)
	feed := func(rate int64, d time.Duration) {
		for end := now.Add(d); now.Before(end); now = now.Add(100 * time.Millisecond) {
			g.bytes.Add(rate / 10)
			g.step(now)
		}
	}
	feed(10e6, 20*time.Second)
	g.request(now, 100*time.Millisecond)
	if g.phase != flowProbeIdle {
		t.Fatal("a probe started at a steady rate")
	}
	feed(2.5e6, 3*time.Second)
	g.request(now, 100*time.Millisecond)
	if g.phase == flowProbeIdle {
		t.Fatal("no probe once the rate fell to a quarter")
	}
}
