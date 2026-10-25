package splithttp

import (
	"testing"
	"time"
)

// rounds feeds e one round each 100 ms from start: the queue and the bytes
// in flight of each step, with caps as large as what is in flight unless a
// third value gives them, against a 20 ms setpoint. What the caps fell by
// since the step before counts as the controller's cut unless a fourth value
// gives the cut. It returns the last gain.
func rounds(e *flowEffect, start time.Time, steps [][]int64) float64 {
	g := e.value()
	var prev int64
	for i, s := range steps {
		caps := s[1]
		if len(s) > 2 {
			caps = s[2]
		}
		cut := max(0, prev-caps)
		if len(s) > 3 {
			cut = s[3]
		}
		if i > 0 {
			e.cutBy(float64(cut))
		}
		prev = caps
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
	g := rounds(&e, time.Now(), [][]int64{{100, 1000}, {110, 700}, {120, 1000, 1000}, {85, 500, 1000}, {80, 450, 1000}})
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
	g := rounds(&e, time.Now(), [][]int64{{900, 1000}, {950, 700}, {1000, 1100, 1100, 0}, {800, 900, 900, 0}, {600, 700, 700, 0}})
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
		w.pi(w.mark.Add(st.rtt), st, h2InitWindow, 1<<30, tc.gain, 0)
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
	w.pi(w.mark.Add(st.rtt), st, h2InitWindow, 1<<30, 0, 0)
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
		w.pi(w.mark.Add(st.minRTT), st, h2InitWindow, 1<<30, 0, 0)
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
	t.Logf("before the cut: %+v", c.effect)
	c.effect.cutBy(300 << 10)
	t.Logf("after the cut: %+v", c.effect)
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
	w.pi(w.mark.Add(st.minRTT), st, h2InitWindow, 1<<30, 0, 0)
	if float64(w.cap) > float64(1<<20)*(1+flowPIMaxStep) {
		t.Fatalf("cap %d from %d in one step", w.cap, 1<<20)
	}
}

// TestFlowEffectCountsSlowDownload has two downloads beside a queue that does
// not move, one of which returns no credit in the round before a cut, as one
// beside a long queue does. Its cap stays in the sum: the cut of 300 KiB is
// under a fifth of the 2 MiB of caps, not judged yet, and the gain stays 1.
// Taken out of the sum, the same cut is three tenths of 1 MiB, judged against
// a queue that stood, and the gain falls to none.
func TestFlowEffectCountsSlowDownload(t *testing.T) {
	fast, slow := &flowStream{}, &flowStream{}
	fast.down.cap, slow.down.cap = 1<<20, 1<<20
	c := &flowConn{streams: map[uint32]*flowStream{1: fast, 3: slow}, kOK: true}
	c.kstat = tcpStats{rtt: 300 * time.Millisecond, minRTT: 100 * time.Millisecond, inFlight: 1 << 20}
	now := time.Now()
	fast.down.returned, slow.down.returned = 1, 1
	c.cutGain(now)
	// The slow download returns nothing in the next round.
	now = now.Add(200 * time.Millisecond)
	fast.down.returned = 2
	c.cutGain(now)
	c.effect.cutBy(300 << 10)
	// The cut lands: what is in flight falls three tenths; the queue stands.
	now = now.Add(200 * time.Millisecond)
	fast.down.returned = 3
	c.kstat.inFlight = 700 << 10
	if g := c.cutGain(now); g != 1 {
		t.Fatalf("gain %v: the slow download's cap left the sum, and a cut under a fifth of the caps was judged", g)
	}
}

// TestFlowEffectNoiseIsNoCut is a held cap beside other traffic in the
// minute after cuts lost their gain: a loss halves what is in flight, the
// caps follow the round trip down a quarter, and the other traffic's queue
// dips a tenth, all at once. None of it is a cut of the controller's, and the
// gain stays none.
func TestFlowEffectNoiseIsNoCut(t *testing.T) {
	var e flowEffect
	g := rounds(&e, time.Now(), [][]int64{{1000, 2000}, {1010, 1400}, {1300, 2800, 2800, 0}, {1170, 1400, 2100, 0}, {1150, 1300, 2000, 0}})
	if g != 0 {
		t.Fatalf("gain %v from a loss, a follow and a dip together", g)
	}
}

// TestFlowEffectHalvedQueueGivesGainBack is a queue cuts did nothing against
// that then halves, drained by the client's other connections: the cuts have
// their full gain back.
func TestFlowEffectHalvedQueueGivesGainBack(t *testing.T) {
	var e flowEffect
	if g := rounds(&e, time.Now(), [][]int64{{100, 1000}, {105, 700}, {80, 700, 700, 0}, {50, 700, 700, 0}}); g != 1 {
		t.Fatalf("gain %v once the queue halved", g)
	}
}

// TestFlowEffectCutMustLand is a cut of three tenths of the caps that what
// is in flight has not come down by yet: the queue cannot have answered it,
// and the gain stays full.
func TestFlowEffectCutMustLand(t *testing.T) {
	var e flowEffect
	if g := rounds(&e, time.Now(), [][]int64{{100, 1000}, {105, 1000, 700, 300}}); g != 1 {
		t.Fatalf("gain %v for a cut that has not landed", g)
	}
}

// TestFlowPIReturnsCut is pi over a queue far above the setpoint: it returns
// the bytes it took off the cap, scaled by the gain.
func TestFlowPIReturnsCut(t *testing.T) {
	st := tcpStats{rtt: 300 * time.Millisecond, minRTT: 100 * time.Millisecond}
	for _, gain := range []float64{1, 0.5} {
		w := flowWindow{cap: 1 << 20, mark: time.Now()}
		w.returned = 1 << 20
		cut := w.pi(w.mark.Add(st.rtt), st, h2InitWindow, 1<<30, gain, 0)
		if got := float64(1<<20 - w.cap); cut <= 0 || got < cut-1 || got > cut+1 {
			t.Fatalf("gain %v: pi returned %v, the cap fell by %v", gain, cut, got)
		}
	}
}

// TestFlowPIReturnsCutThatLanded is pi cutting a cap just over init: it
// returns what the cap fell by, not the step it could not take.
func TestFlowPIReturnsCutThatLanded(t *testing.T) {
	st := tcpStats{rtt: 300 * time.Millisecond, minRTT: 100 * time.Millisecond}
	w := flowWindow{cap: h2InitWindow + 1000, mark: time.Now()}
	w.returned = 1 << 20
	if cut := w.pi(w.mark.Add(st.rtt), st, h2InitWindow, 1<<30, 1, 0); cut > 1000 {
		t.Fatalf("pi returned %v for a cap that could fall by 1000", cut)
	}
}

// TestFlowEffectDoesNotAttributePreCutFlightDrop (from the review of the
// change) has what is in flight fall before the controller cuts: the cut is
// judged from the round before it, and what is in flight has not come down
// since.
func TestFlowEffectDoesNotAttributePreCutFlightDrop(t *testing.T) {
	var e flowEffect
	start := time.Unix(1, 0)
	e.note(start, 200*time.Millisecond, 100*time.Millisecond,
		20*time.Millisecond, 1024, 1024)

	// Flight falls before any controller cut; queue delay rises.
	e.note(start.Add(time.Second), 300*time.Millisecond,
		100*time.Millisecond, 20*time.Millisecond, 768, 1024)

	e.cutBy(256)
	gain := e.note(start.Add(2*time.Second), 275*time.Millisecond,
		100*time.Millisecond, 20*time.Millisecond, 768, 768)
	if gain != 1 {
		t.Fatalf("gain=%g: no flight reduction occurred after the cut", gain)
	}
}
