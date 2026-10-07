package splithttp

import (
	"testing"
	"time"
)

func TestFlowWindowRamp(t *testing.T) {
	const rtt = 50 * time.Millisecond
	start := time.Unix(0, 0)
	w := flowWindow{cap: flowStartWindow}
	step := func(at time.Duration, credit int64) {
		w.returned += credit
		w.adjust(start.Add(at), rtt, h2InitWindow, 1<<30, true, false)
	}

	step(0, 32<<10)
	step(10*time.Millisecond, 200<<10)
	if want := int32(h2InitWindow + 2*(232<<10)); w.cap != want {
		t.Fatalf("before the first round trip the cap should open with every credit: got %d, want %d", w.cap, want)
	}

	step(rtt, 56<<10)
	step(2*rtt, 512<<10)
	if want := int32(3 << 20); w.cap != want {
		t.Fatalf("a reader doubling its rate should get room for the sender doubling too: got %d, want %d", w.cap, want)
	}

	step(3*rtt, 512<<10)
	step(4*rtt, 2<<20)
	if want := int32(4 << 20); w.cap != want {
		t.Fatalf("after the reader stopped speeding up the cap should follow twice its rate: got %d, want %d", w.cap, want)
	}
}

func TestFlowLearnedHalfLife(t *testing.T) {
	var l flowLearned
	start := time.Unix(0, 0)
	l.note(start, h2InitWindow, 2<<20)
	if got, want := l.value(start.Add(flowLearnHalf), h2InitWindow), int32(h2InitWindow+(2<<20-h2InitWindow)/2); got != want {
		t.Fatalf("learned cap after one half-life: got %d, want %d", got, want)
	}
}

func TestFlowWindowHold(t *testing.T) {
	const rtt = 50 * time.Millisecond
	start := time.Unix(0, 0)
	w := flowWindow{cap: flowStartWindow}
	for i, credit := range []int64{32 << 10, 200 << 10, 512 << 10, 1 << 20} {
		w.returned += credit
		w.adjust(start.Add(time.Duration(i)*rtt), rtt, h2InitWindow, 1<<30, true, true)
	}
	if w.cap != flowStartWindow {
		t.Fatalf("the cap grew to %d while a queue was building", w.cap)
	}
}

func TestFlowQueueing(t *testing.T) {
	ms := time.Millisecond
	for _, tc := range []struct {
		rtt, min time.Duration
		ok       bool
		want     int
	}{
		{60 * ms, 50 * ms, true, 0},
		{110 * ms, 50 * ms, true, 1},
		{160 * ms, 50 * ms, true, 2},
		{10 * ms, ms, true, 0},
		{30 * ms, ms, true, 1},
		{50 * ms, ms, true, 2},
		{500 * ms, 50 * ms, false, 0},
	} {
		c := &flowConn{tcp: fakeRawConn{}, kAt: time.Unix(0, 0), kstat: tcpStats{rtt: tc.rtt, minRTT: tc.min}, kOK: tc.ok}
		if got := c.queueing(time.Unix(0, 0)); got != tc.want {
			t.Errorf("rtt %v over min %v (stats %v): got %d, want %d", tc.rtt, tc.min, tc.ok, got, tc.want)
		}
	}
}

type fakeRawConn struct{}

func (fakeRawConn) Control(func(uintptr)) error    { return nil }
func (fakeRawConn) Read(func(uintptr) bool) error  { return nil }
func (fakeRawConn) Write(func(uintptr) bool) error { return nil }
