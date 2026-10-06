package splithttp

import (
	"testing"
	"time"
)

func TestFlowWindowModel(t *testing.T) {
	const rtprop = 100 * time.Millisecond
	start := time.Unix(0, 0)
	w := flowWindow{cap: 4 << 20, mark: start, ramped: true}
	now := start
	feed := func(rounds int, perRound int64) {
		for range rounds {
			now = now.Add(rtprop)
			w.returned += perRound
			w.model(now, rtprop, h2InitWindow, 1<<30)
		}
	}

	// 10 MB/s over a 100 ms path: 1 MB in flight, plus a quarter.
	feed(3, 1_000_000)
	if want := int32(1_250_000); w.cap != want {
		t.Fatalf("steady reader: cap %d, want %d", w.cap, want)
	}

	// A slower reader keeps the fastest of the last rounds for a while.
	feed(5, 200_000)
	if want := int32(1_250_000); w.cap != want {
		t.Fatalf("within the filter window: cap %d, want %d", w.cap, want)
	}
	feed(flowModelRounds, 200_000)
	if want := int32(250_000); w.cap != want {
		t.Fatalf("after the filter window: cap %d, want %d", w.cap, want)
	}

	// An idle reader never takes the cap below init.
	feed(flowModelRounds, 0)
	if w.cap != h2InitWindow {
		t.Fatalf("idle reader: cap %d, want init", w.cap)
	}
}

func TestFlowWindowModelSeed(t *testing.T) {
	const rtprop = 100 * time.Millisecond
	start := time.Unix(0, 0)
	w := flowWindow{cap: 4 << 20, mark: start, ramped: true, prev: 1_000_000}
	w.returned = 100_000
	w.model(start.Add(rtprop), rtprop, h2InitWindow, 1<<30)
	if want := int32(1_250_000); w.cap != want {
		t.Fatalf("a slow first round dropped the cap to %d, want %d from the ramp", w.cap, want)
	}
}
