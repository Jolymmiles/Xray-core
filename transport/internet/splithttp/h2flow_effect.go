package splithttp

import "time"

// A server cuts its downloads against the queue its kernel sees. Where the
// queue is its own, it shortens as the cuts take effect; where other traffic
// keeps it full, it does not, and cut after cut, a PI controller's integral
// winding up against an error nothing it does removes, takes the downloads
// to init per round trip. So each connection measures what its cuts do:
// over an episode of standing queue, how far the queue fell from its peak
// for how far a cut brought down what the kernel has in flight, the caps
// and the rate the caps allow over the round trip, the least of the three.
// What is in flight, as a cut lands only once the data in flight comes down
// to it: where the queue is the server's own, by Little's law it falls with
// what is in flight, and where it is foreign only the download's share of
// the rate does. The caps, as a loss beside other traffic drops what is in
// flight while other senders back off, and the queue with it. The rate, as a
// cap that follows the round trip down is no cut either.
//
// Cuts are scaled by that gain; growth is not, and where cuts have less
// gain the caps follow the round trip by as much more, so the download keeps
// its rate. A small gain is no noise to be cut off: where the client's
// connections share a queue of the server's own, each one's cut moves the
// queue by its share, and all of them cutting by their shares drain it.
const (
	// flowEffectProbe is how far a cut must bring the three down from their
	// peaks before the queue's answer counts: until then cuts work in full.
	flowEffectProbe = 0.2
	// An episode is a queue over flowEffectAbove times the setpoint: the PI
	// controller holds the queue at the setpoint, and an episode that took
	// that for standing queue would never end, and judge a later queue by
	// an old peak. flowEffectClear rounds in a row back under it end one.
	flowEffectAbove = 1.25
	flowEffectClear = 2
)

type flowEffect struct {
	at        time.Time
	queue     float64
	active    bool
	clear     int
	flightTop float64
	capsTop   float64
	rateTop   float64
	qTop      float64
	gain      float64
}

// note takes the round trip the kernel reads and that of the empty path, the
// setpoint, the bytes in flight and the caps of the downloads that took data,
// once per round. It returns the gain cuts are scaled by: 1 outside an
// episode and until a cut has brought the three down by flowEffectProbe;
// then the share by which the queue fell for the share of that cut, as of
// the last such cut.
func (e *flowEffect) note(now time.Time, rtt, minRTT, set time.Duration, inFlight, caps int64) float64 {
	e.at = now
	// The kernel's smoothed round trip, as it is: smoothing it again would
	// have the queue lag behind what is in flight by rounds, and a cut that
	// took effect read as one that did not.
	e.queue = float64(rtt - minRTT)
	x, c := float64(inFlight), float64(caps)
	r := c / float64(max(rtt, time.Millisecond))
	if e.queue <= flowEffectAbove*float64(set) {
		if e.clear++; e.clear >= flowEffectClear {
			e.active = false
		}
		return e.value()
	}
	e.clear = 0
	if !e.active {
		e.active, e.gain = true, 1
		e.flightTop, e.capsTop, e.rateTop, e.qTop = x, c, r, e.queue
		return 1
	}
	e.flightTop, e.capsTop, e.rateTop, e.qTop = max(e.flightTop, x), max(e.capsTop, c), max(e.rateTop, r), max(e.qTop, e.queue)
	// Without a cut deep enough to judge by, the gain stays what the last one
	// showed: a cap held where cuts did nothing brings what is in flight back
	// to its peak, and must not take that for leave to cut again.
	if cut := min(1-x/e.flightTop, 1-c/e.capsTop, 1-r/e.rateTop); cut >= flowEffectProbe {
		e.gain = min(max((1-e.queue/e.qTop)/cut, 0), 1)
	}
	return e.gain
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
