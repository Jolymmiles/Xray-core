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
		w.adjust(start.Add(at), rtt, h2InitWindow, 1<<30, true)
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
