package splithttp

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// A client's governed connections to one server share the path to it. One
// connection cannot tell a path whose round trip has risen from a queue its
// siblings and it fill: in both its windows sit at init with the round trip
// over the kernel's floor, and a wider window of its own takes a larger share
// of a full link as it fills an empty one. The client as a whole can: where
// the path has room, wider windows on every connection carry more in all;
// where the client fills the link, they carry the same and only queue. So the
// connections of a group probe together, and a path that answers the probe
// is one whose round trip has moved.
const (
	// flowProbeGain widens the windows during a probe, and flowProbeAnswer
	// is the rise in what the group carries that counts as an answer.
	flowProbeGain   = 1.25
	flowProbeAnswer = 1.15
	// A probe that got no answer is not tried again for flowProbeQuiet, twice
	// that after each further one up to flowProbeQuietMost: a client that
	// fills its link keeps its own queue, and each probe adds to it for a
	// while. One that did is tried again after flowProbeAgain.
	flowProbeQuiet     = 30 * time.Second
	flowProbeQuietMost = 5 * time.Minute
	flowProbeAgain     = 10 * time.Second
	// flowProbeAfter is how long downloads sit at init under a raised round
	// trip before their connection asks for a probe.
	flowProbeAfter = 5 * time.Second
	// flowProbeLeast is the least time each half of a probe measures over.
	flowProbeLeast = 400 * time.Millisecond
	// A probe is only asked for once what the group carries has fallen under
	// flowProbeDrop of the most it carried lately, the most halving every
	// flowProbePeakHalf: a path whose round trip rose took the rate with it,
	// while a client that fills its link carries the same as before.
	flowProbeDrop     = 0.5
	flowProbePeakHalf = time.Minute
)

const (
	flowProbeIdle = iota
	flowProbeBefore
	flowProbeWide
)

// flowGroup is what a client's connections to one server share: the bytes
// they have received, and the probe.
type flowGroup struct {
	key   string
	refs  int
	bytes atomic.Int64

	mu    sync.Mutex
	phase int
	at    time.Time
	mark  int64
	span  time.Duration
	rate  float64
	moved time.Time
	next  time.Time
	quiet time.Duration
	// cur is what the group carried over the last second, peak the most it
	// carried lately; rAt and rMark start the second.
	cur, peak float64
	rAt       time.Time
	rMark     int64
}

var flowGroups = struct {
	sync.Mutex
	m map[string]*flowGroup
}{m: map[string]*flowGroup{}}

func joinFlowGroup(key string) *flowGroup {
	flowGroups.Lock()
	defer flowGroups.Unlock()
	g := flowGroups.m[key]
	if g == nil {
		g = &flowGroup{key: key}
		flowGroups.m[key] = g
	}
	g.refs++
	return g
}

func (g *flowGroup) leave() {
	flowGroups.Lock()
	defer flowGroups.Unlock()
	if g.refs--; g.refs <= 0 {
		delete(flowGroups.m, g.key)
	}
}

// request starts a probe unless one runs or one ended lately. rtt is the
// round trip the requester sees; each half measures over four of them.
func (g *flowGroup) request(now time.Time, rtt time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.phase != flowProbeIdle || now.Before(g.next) || g.cur >= flowProbeDrop*g.peak {
		return
	}
	g.phase, g.at, g.mark, g.span = flowProbeBefore, now, g.bytes.Load(), max(4*rtt, flowProbeLeast)
}

// step moves the probe on and reports whether windows are to be wide now,
// and when the path last answered a probe.
func (g *flowGroup) step(now time.Time) (wide bool, moved time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.rAt.IsZero() {
		g.rAt, g.rMark = now, g.bytes.Load()
	} else if d := now.Sub(g.rAt); d >= time.Second {
		got := g.bytes.Load()
		g.cur = float64(got-g.rMark) / d.Seconds()
		g.peak = max(g.cur, g.peak*math.Exp2(-d.Seconds()/flowProbePeakHalf.Seconds()))
		g.rAt, g.rMark = now, got
	}
	if g.phase != flowProbeIdle && now.Sub(g.at) >= g.span {
		got := g.bytes.Load()
		rate := float64(got-g.mark) / now.Sub(g.at).Seconds()
		switch g.phase {
		case flowProbeBefore:
			g.phase, g.rate = flowProbeWide, rate
		case flowProbeWide:
			g.phase = flowProbeIdle
			if g.rate > 0 && rate >= flowProbeAnswer*g.rate {
				g.moved, g.next, g.quiet = now, now.Add(flowProbeAgain), 0
			} else {
				g.quiet = min(max(2*g.quiet, flowProbeQuiet), flowProbeQuietMost)
				g.next = now.Add(g.quiet)
			}
		}
		g.at, g.mark = now, got
	}
	return g.phase == flowProbeWide, g.moved
}
