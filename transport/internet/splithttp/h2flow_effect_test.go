package splithttp

import (
	"testing"
	"time"
)

// rounds feeds e one round each 100 ms from start: the queue and the bytes
// in flight of each step, with caps as large as what is in flight unless a
// third value gives them, against a 20 ms setpoint. It returns the last gain.
func rounds(e *flowEffect, start time.Time, steps [][]int64) float64 {
	g := e.value()
	for i, s := range steps {
		caps := s[1]
		if len(s) > 2 {
			caps = s[2]
		}
		g = e.note(start.Add(time.Duration(i)*100*time.Millisecond), time.Duration(100+s[0])*time.Millisecond, 100*time.Millisecond, 20*time.Millisecond, s[1], caps)
	}
	return g
}

// TestFlowEffectOwnQueue is a queue that falls as what is in flight does:
// the cuts work, and keep their full gain.
func TestFlowEffectOwnQueue(t *testing.T) {
	var e flowEffect
	g := rounds(&e, time.Now(), [][]int64{{100, 1000}, {90, 900}, {70, 750}, {50, 600}})
	if g != 1 {
		t.Fatalf("gain %v for a queue that fell with what is in flight", g)
	}
}

// TestFlowEffectForeignQueue is a queue that does not move when what is in
// flight falls by a third: the cuts do nothing, and stop.
func TestFlowEffectForeignQueue(t *testing.T) {
	var e flowEffect
	g := rounds(&e, time.Now(), [][]int64{{100, 1000}, {105, 900}, {110, 750}, {120, 650}})
	if g != 0 {
		t.Fatalf("gain %v for a queue that grew while what is in flight fell", g)
	}
}

// TestFlowEffectWaitsForCut is a queue that stands while what is in flight
// has not yet come down: a cut that has not landed says nothing, and cuts
// keep their full gain.
func TestFlowEffectWaitsForCut(t *testing.T) {
	var e flowEffect
	g := rounds(&e, time.Now(), [][]int64{{100, 1000}, {120, 1100}, {140, 1200}, {150, 1050}})
	if g != 1 {
		t.Fatalf("gain %v before what is in flight fell by %v", g, flowEffectProbe)
	}
}

// TestFlowEffectKeepsGain is a cap held where cuts did nothing: what is in
// flight climbs back to its peak, and the gain stays as the last cut
// showed it, so that the climb is not taken for leave to cut again.
func TestFlowEffectKeepsGain(t *testing.T) {
	var e flowEffect
	g := rounds(&e, time.Now(), [][]int64{{100, 1000}, {110, 700}, {130, 900}, {160, 1000}, {200, 1100}})
	if g != 0 {
		t.Fatalf("gain %v once what is in flight came back", g)
	}
}

// TestFlowEffectEpisodeEnds is a queue back under the bar for two rounds:
// the episode ends, cuts have their full gain again, and the next queue is
// judged by its own peak, not the last one's.
func TestFlowEffectEpisodeEnds(t *testing.T) {
	var e flowEffect
	start := time.Now()
	rounds(&e, start, [][]int64{{100, 1000}, {110, 700}, {20, 700}})
	if g := e.value(); g != 0 {
		t.Fatalf("one round under the bar ended the episode: gain %v", g)
	}
	if g := rounds(&e, start.Add(300*time.Millisecond), [][]int64{{20, 700}}); g != 1 {
		t.Fatalf("gain %v after two rounds under the bar", g)
	}
	if g := rounds(&e, start.Add(400*time.Millisecond), [][]int64{{60, 800}, {40, 600}}); g != 1 {
		t.Fatalf("gain %v for a new queue that falls with its cuts", g)
	}
}

// TestFlowEffectLossIsNoCut is a held cap beside other traffic: a loss
// halves what is in flight and the other senders back off, so the queue
// falls with it, but the caps did not move. That is no cut of the server's,
// and the gain stays as it was.
func TestFlowEffectLossIsNoCut(t *testing.T) {
	var e flowEffect
	g := rounds(&e, time.Now(), [][]int64{{100, 1000}, {110, 700}, {120, 1000, 1000}, {60, 500, 1000}, {50, 450, 1000}})
	if g != 0 {
		t.Fatalf("gain %v after a loss under a held cap", g)
	}
}

// TestFlowEffectFollowIsNoCut is a held cap that follows the round trip down
// as the foreign queue ebbs: caps and what is in flight fall, the queue with
// them, but the rate the caps allow does not. That is no cut, and the gain
// stays as it was.
func TestFlowEffectFollowIsNoCut(t *testing.T) {
	var e flowEffect
	g := rounds(&e, time.Now(), [][]int64{{900, 1000}, {950, 700}, {1000, 1100}, {800, 900}, {600, 700}})
	if g != 0 {
		t.Fatalf("gain %v for a cap that followed the round trip down", g)
	}
}

// TestFlowPIGainHolds is the PI controller over a queue far above the
// setpoint: with the full gain it cuts; with none it does not, and the cap
// follows the round trip as it grows, so the reader keeps its rate.
func TestFlowPIGainHolds(t *testing.T) {
	st := tcpStats{rtt: 300 * time.Millisecond, minRTT: 100 * time.Millisecond}
	for _, tc := range []struct {
		gain float64
		cut  bool
	}{{1, true}, {0, false}} {
		w := flowWindow{cap: 1 << 20, mark: time.Now(), piRTT: 250 * time.Millisecond}
		w.returned = 1 << 20
		w.pi(w.mark.Add(st.rtt), st, h2InitWindow, 1<<30, tc.gain)
		if got := w.cap < 1<<20; got != tc.cut {
			t.Fatalf("gain %v: cap %d from %d", tc.gain, w.cap, 1<<20)
		}
		if !tc.cut && float64(w.cap) < float64(1<<20)*1.15 {
			t.Fatalf("gain 0: cap %d did not follow the round trip up a fifth", w.cap)
		}
	}
}

// TestFlowPIFollowsOnlyABindingCap is a cap that some other limit keeps the
// reader under: it does not follow the round trip up, so that a later cut
// still lands on it.
func TestFlowPIFollowsOnlyABindingCap(t *testing.T) {
	st := tcpStats{rtt: 300 * time.Millisecond, minRTT: 100 * time.Millisecond}
	w := flowWindow{cap: 4 << 20, mark: time.Now(), piRTT: 250 * time.Millisecond}
	w.returned = 1 << 20
	w.pi(w.mark.Add(st.rtt), st, h2InitWindow, 1<<30, 0)
	if w.cap > 4<<20 {
		t.Fatalf("cap %d grew over the %d the reader is held under", w.cap, 4<<20)
	}
}

// TestFlowEffectShare is one of three connections that share a queue of the
// server's own: its cut halves what it has in flight, and the queue falls by
// its share of it. The gain is that share, not none, so that each cutting
// by its share drains the queue.
func TestFlowEffectShare(t *testing.T) {
	var e flowEffect
	g := rounds(&e, time.Now(), [][]int64{{110, 480}, {100, 400}, {85, 240}})
	if g < 0.3 || g > 0.6 {
		t.Fatalf("gain %v for a share of a third", g)
	}
}

// TestFlowPIReaderBesideQueue is a reader that takes all it is given beside
// a queue of over a second: per round of the empty path it copies only that
// round's share of the cap. It does not limit itself, and its cap holds.
func TestFlowPIReaderBesideQueue(t *testing.T) {
	st := tcpStats{rtt: 1500 * time.Millisecond, minRTT: 150 * time.Millisecond}
	w := flowWindow{cap: 4 << 20, mark: time.Now()}
	for range 2 * flowShrinkAfter {
		w.returned += int64(w.cap) * int64(st.minRTT) / int64(st.rtt)
		w.pi(w.mark.Add(st.minRTT), st, h2InitWindow, 1<<30, 0)
	}
	if w.cap < 4<<20 {
		t.Fatalf("cap %d, from %d, for a reader that takes all it is given", w.cap, 4<<20)
	}
}

// TestFlowEffectCountsDownloadsOnly is a connection with a download and a
// stream that carries nothing beside it, as an upload's. The download's
// cut is a cut of the connection's: the idle stream's cap does not dilute it.
func TestFlowEffectCountsDownloadsOnly(t *testing.T) {
	down := &flowStream{}
	down.down.cap = 1 << 20
	idle := &flowStream{}
	idle.down.cap = 4 << 20
	c := &flowConn{streams: map[uint32]*flowStream{1: down, 3: idle}, kOK: true}
	c.kstat = tcpStats{rtt: 300 * time.Millisecond, minRTT: 100 * time.Millisecond, inFlight: 1 << 20}
	now := time.Now()
	down.down.returned = 1
	c.cutGain(now)
	// The download is cut by a third and takes data; the queue stands.
	down.down.cap, down.down.returned = 700<<10, 2
	c.kstat.inFlight = 700 << 10
	if g := c.cutGain(now.Add(time.Second)); g != 0 {
		t.Fatalf("gain %v for a download cut against a queue that did not move", g)
	}
}

// TestFlowPIFollowsOneStep is a round trip that rose tenfold in one round:
// a cut that does not move the queue has the cap follow it by no more than
// pi's own largest step.
func TestFlowPIFollowsOneStep(t *testing.T) {
	st := tcpStats{rtt: time.Second, minRTT: 100 * time.Millisecond}
	w := flowWindow{cap: 1 << 20, mark: time.Now(), piRTT: 100 * time.Millisecond}
	w.returned = 1 << 20
	w.pi(w.mark.Add(st.minRTT), st, h2InitWindow, 1<<30, 0)
	if float64(w.cap) > float64(1<<20)*(1+flowPIMaxStep) {
		t.Fatalf("cap %d from %d in one step", w.cap, 1<<20)
	}
}
