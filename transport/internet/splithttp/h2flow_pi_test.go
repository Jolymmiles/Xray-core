package splithttp

import (
	"testing"
	"time"
)

func TestFlowWindowPI(t *testing.T) {
	ms := time.Millisecond
	start := time.Unix(0, 0)
	step := func(w *flowWindow, st tcpStats, copied int64) {
		w.returned += copied
		w.pi(w.mark.Add(st.minRTT), st, h2InitWindow, 1<<30)
	}

	// No queue: the cap grows, by at most half per round trip.
	w := flowWindow{cap: 1 << 20, mark: start}
	step(&w, tcpStats{rtt: 100 * ms, minRTT: 100 * ms}, 1<<20)
	if w.cap < 5<<18 || w.cap > 3<<19 {
		t.Fatalf("empty path: cap %d", w.cap)
	}

	// A queue of twice the setpoint shrinks it.
	w = flowWindow{cap: 1 << 20, mark: start}
	step(&w, tcpStats{rtt: 150 * ms, minRTT: 100 * ms}, 1<<20)
	if w.cap >= 1<<20 {
		t.Fatalf("queue at twice the setpoint: cap %d", w.cap)
	}

	// Jitter raises the setpoint: 30 ms over the floor with 20 ms variance
	// is below it, so the cap still grows.
	w = flowWindow{cap: 1 << 20, mark: start}
	step(&w, tcpStats{rtt: 130 * ms, minRTT: 100 * ms, rttVar: 20 * ms}, 1<<20)
	if w.cap <= 1<<20 {
		t.Fatalf("jitter taken for queue: cap %d", w.cap)
	}

	// A reader taking less than a quarter of the window does not grow it,
	// and after flowShrinkAfter rounds it shrinks.
	w = flowWindow{cap: 4 << 20, mark: start}
	for range flowShrinkAfter {
		step(&w, tcpStats{rtt: 100 * ms, minRTT: 100 * ms}, 256<<10)
	}
	if w.cap >= 4<<20 {
		t.Fatalf("self-limited reader: cap %d", w.cap)
	}

	// Never below init, never above the limit.
	w = flowWindow{cap: h2InitWindow, mark: start}
	step(&w, tcpStats{rtt: 500 * ms, minRTT: 100 * ms}, 0)
	if w.cap != h2InitWindow {
		t.Fatalf("below init: %d", w.cap)
	}
}

// TestFlowWindowPISettles drives the controller against a model path, a
// FIFO bottleneck whose queue is what the window holds beyond the
// bandwidth-delay product, and checks it settles near the setpoint instead
// of cycling.
func TestFlowWindowPISettles(t *testing.T) {
	for _, path := range []struct {
		name   string
		rate   int64 // bytes per second
		minRTT time.Duration
	}{
		{"100 Mbit/s, 50 ms", 12_500_000, 50 * time.Millisecond},
		{"100 Mbit/s, 150 ms", 12_500_000, 150 * time.Millisecond},
		{"20 Mbit/s, 300 ms", 2_500_000, 300 * time.Millisecond},
		{"1 Gbit/s, 20 ms", 125_000_000, 20 * time.Millisecond},
	} {
		bdp := path.rate * int64(path.minRTT) / int64(time.Second)
		w := flowWindow{cap: int32(4 * bdp), mark: time.Unix(0, 0)}
		var queue time.Duration
		var tail []time.Duration
		last := w.cap // the queue answers the window a round trip late
		for round := range 200 {
			queue = time.Duration(max(int64(last)-bdp, 0) * int64(time.Second) / path.rate)
			last = w.cap
			st := tcpStats{rtt: path.minRTT + queue, minRTT: path.minRTT}
			w.returned += path.rate * int64(st.rtt) / int64(time.Second)
			w.pi(w.mark.Add(st.rtt), st, h2InitWindow, 1<<30)
			if round >= 150 {
				tail = append(tail, queue)
			}
		}
		set := max(path.minRTT/4, flowPIMinSet)
		lo, hi := tail[0], tail[0]
		for _, q := range tail {
			lo, hi = min(lo, q), max(hi, q)
		}
		if hi > 2*set || lo < set/4 || hi-lo > set {
			t.Errorf("%s: queue between %v and %v, setpoint %v", path.name, lo, hi, set)
		}
	}
}
