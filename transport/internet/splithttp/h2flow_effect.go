package splithttp

import "time"

// A server cuts its downloads against the queue its kernel sees. Where the
// queue is its own, it shortens as the cuts take effect; where other traffic
// keeps it full, it does not, and cut after cut, a PI controller's integral
// winding up against an error nothing it does removes, takes the downloads
// to init per round trip. So each connection measures what its cuts do:
// over an episode of standing queue, how far the queue fell from its peak
// for the share of the caps the controller cut, once the cut has landed in
// what the kernel has in flight. Where the queue is the server's own, by
// Little's law it falls with what is in flight; where it is foreign only the
// download's share of the rate does. Only the controller's own cuts count: a
// loss that drops what is in flight, the caps following the round trip down
// and a dip of other traffic's queue move together now and then, and read
// together as a cut that worked.
//
// Cuts are scaled by that gain; growth is not, and where cuts have less
// gain the caps follow the round trip by as much more, so the download keeps
// its rate. A small gain is no noise to be cut off: where the client's
// connections share a queue of the server's own, each one's cut moves the
// queue by its share, and all of them cutting by their shares drain it.
const (
	// flowEffectProbe is the share of the caps a cut must take, and of what
	// is in flight it must bring down, before the queue's answer counts:
	// until then cuts work in full.
	flowEffectProbe = 0.2
	// An episode is a queue over flowEffectAbove times the setpoint: the PI
	// controller holds the queue at the setpoint, and an episode that took
	// that for standing queue would never end, and judge a later queue by
	// an old peak. flowEffectClear rounds in a row back under it end one.
	flowEffectAbove = 1.25
	flowEffectClear = 2
	// flowEffectRecent is the round trips of the empty path, and at least a
	// second, within which a download that took data counts as taking it.
	flowEffectRecent = 8
)

type flowEffect struct {
	at        time.Time
	queue     float64
	active    bool
	clear     int
	flightTop float64
	capsTop   float64
	qTop      float64
	cut       float64
	gain      float64
	// flight and caps are what the last note saw.
	flight, caps float64
}

// cutBy notes bytes the controller cut from the caps against the queue. The
// first cut of a measurement is judged from the last note before it: what was
// in flight and the queue then, not their peaks since the measurement began,
// which a drop before the cut would otherwise count for it.
func (e *flowEffect) cutBy(bytes float64) {
	if bytes <= 0 {
		return
	}
	if e.active && e.cut == 0 {
		e.flightTop, e.capsTop, e.qTop = e.flight, e.caps, e.queue
	}
	e.cut += bytes
}

// note takes the round trip the kernel reads and that of the empty path, the
// setpoint, the bytes in flight and the caps of the downloads that took data,
// once per round. It returns the gain cuts are scaled by: 1 outside an
// episode, until the controller has cut flowEffectProbe of the caps and what
// is in flight has come down as far, and once the queue halves; otherwise
// the share by which the queue fell for the share of the last such cut.
func (e *flowEffect) note(now time.Time, rtt, minRTT, set time.Duration, inFlight, caps int64) float64 {
	e.at = now
	// The kernel's smoothed round trip, as it is: smoothing it again would
	// have the queue lag behind what is in flight by rounds, and a cut that
	// took effect read as one that did not.
	e.queue = float64(rtt - minRTT)
	x, c := float64(inFlight), float64(caps)
	e.flight, e.caps = x, c
	if e.queue <= flowEffectAbove*float64(set) {
		if e.clear++; e.clear >= flowEffectClear {
			e.active = false
		}
		return e.value()
	}
	e.clear = 0
	if !e.active {
		e.active, e.gain = true, 1
		e.start(x, c)
		return 1
	}
	// A cut is judged from the round before it, see cutBy: peaks after it,
	// a burst of flight it did not cause or a queue that rose on, would
	// have a fall back from them read as the cut's.
	if e.cut == 0 {
		e.flightTop, e.qTop = max(e.flightTop, x), max(e.qTop, e.queue)
	}
	// A queue that halved since the last judgement drained by the client's
	// own cuts, this connection's or its neighbours': cuts have their gain
	// back. Other traffic's queue at a full buffer wanders by a tenth, and
	// halves only as that traffic leaves.
	if e.gain < 1 && e.queue <= e.qTop/2 {
		e.gain = 1
		e.start(x, c)
		return 1
	}
	// Only what the controller cut counts, and only once it has landed in
	// what is in flight. The caps following the round trip down, a loss that
	// drops what is in flight, and a dip of other traffic's queue each move
	// with the others now and then, and taken together read as a cut that
	// worked. Without a cut deep enough to judge by, the gain stays what the
	// last one showed; without gain the controller does not cut, and the gain
	// stays none until the queue halves or is gone.
	if e.capsTop <= 0 {
		return e.gain
	}
	if cut := min(e.cut/e.capsTop, 1-x/e.flightTop); cut >= flowEffectProbe {
		e.gain = min(max((1-e.queue/e.qTop)/cut, 0), 1)
		e.start(x, c)
	}
	return e.gain
}

// start begins a measurement from now: the next cut is judged from here.
func (e *flowEffect) start(x, c float64) {
	e.flightTop, e.capsTop, e.qTop, e.cut = x, c, e.queue, 0
}

// due reports whether a round has passed since the last note.
func (e *flowEffect) due(now time.Time, round time.Duration) bool {
	return e.at.IsZero() || now.Sub(e.at) >= round
}

func (e *flowEffect) value() float64 {
	if !e.active {
		return 1
	}
	return e.gain
}
