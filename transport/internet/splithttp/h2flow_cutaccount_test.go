package splithttp

import (
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestFlowEffectPostCutSpikeIsNoCut has what is in flight double after a cut
// and come back to where it stood before it, with the queue above where it
// was: nothing fell below the round before the cut, so the cut is not judged
// and the gain stays 1. Peaks raised after the cut took the fall back from
// the spike for the cut's effect.
func TestFlowEffectPostCutSpikeIsNoCut(t *testing.T) {
	var e flowEffect
	t0 := time.Unix(1, 0)
	e.note(t0, 300*time.Millisecond, 100*time.Millisecond, 20*time.Millisecond, 1024, 1024)
	e.cutBy(256)
	e.note(t0.Add(time.Second), 500*time.Millisecond, 100*time.Millisecond, 20*time.Millisecond, 2048, 1024)
	if gain := e.note(t0.Add(2*time.Second), 450*time.Millisecond, 100*time.Millisecond, 20*time.Millisecond, 1024, 768); gain != 1 {
		t.Fatalf("gain=%g: what is in flight never fell below the round before the cut", gain)
	}
}

// TestFlowFinishedDownloadCutNotCounted has the server finish a download and
// the client then return credit on it, as it legally may, beside a long
// queue: what the cut at a long queue takes off that cap is no cut of a
// download that takes part in the gain, and is not noted.
func TestFlowFinishedDownloadCutNotCounted(t *testing.T) {
	h, s := queuedDownload(t)
	h.fromServer(func(fr *http2.Framer) { fr.WriteData(1, true, nil) })
	h.c.mu.Lock()
	done := s.serverDone
	h.c.mu.Unlock()
	if !done {
		t.Fatal("the server did not finish the download")
	}
	credit(h, s)
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if h.c.effect.cut != 0 {
		t.Fatalf("%v bytes of cut noted on a download the server had finished", h.c.effect.cut)
	}
}

// TestFlowPISlowReaderNoOverflow has a reader that took one byte over an hour,
// and a 1 GiB cap over ten seconds, at the last slow round before the cap
// shrinks: the cap shrinks. The cap times the round in nanoseconds wrapped,
// and the cap grew instead.
func TestFlowPISlowReaderNoOverflow(t *testing.T) {
	for _, tc := range []struct {
		cap   int32
		round time.Duration
	}{{4 << 20, time.Hour}, {1 << 30, 10 * time.Second}} {
		now := time.Unix(1e6, 0)
		w := flowWindow{cap: tc.cap, returned: 1, slow: flowShrinkAfter - 1}
		w.mark = now.Add(-tc.round)
		st := tcpStats{rtt: 100 * time.Millisecond, minRTT: 100 * time.Millisecond}
		w.pi(now, st, h2InitWindow, 1<<30, 1)
		if w.cap >= tc.cap {
			t.Fatalf("cap %d after a byte in %v: did not shrink from %d", w.cap, tc.round, tc.cap)
		}
	}
}

// TestFlowLongQueueCutRounding cuts caps one to three bytes over a multiple
// of four at full gain: the cap goes to three quarters as it always did,
// before/4*3.
func TestFlowLongQueueCutRounding(t *testing.T) {
	for _, before := range []int32{1048577, 1048578, 1048579} {
		h, s := queuedDownload(t)
		h.c.mu.Lock()
		s.down.cap = before
		h.c.mu.Unlock()
		if got, want := credit(h, s), before/4*3; got != want {
			t.Fatalf("cap %d cut at full gain to %d, want %d", before, got, want)
		}
	}
}

// TestFlowCoarseClientCutAboveHalfWindow has a client that credits in large
// steps, one that may wait for half of its 4 MiB window before it credits,
// beside a long queue: cut after cut takes its cap no lower than half that
// window and the credit the guard adds, where the download would stop until
// the guard lifts it. A client that credits in small steps is cut on down.
func TestFlowCoarseClientCutAboveHalfWindow(t *testing.T) {
	for _, step := range []uint32{128 << 10, 4 << 10} {
		h, s := queuedDownload(t)
		h.c.mu.Lock()
		s.down.cap = 4 << 20
		floor := int32(h.c.clientInit/2 + flowSmallCredit)
		h.c.mu.Unlock()
		var low int32 = 4 << 20
		for range 8 {
			h.c.mu.Lock()
			s.down.qAt = time.Time{}
			h.c.mu.Unlock()
			h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(1, step) })
			h.c.mu.Lock()
			low = min(low, s.down.cap)
			h.c.mu.Unlock()
		}
		coarse := step >= flowSmallCredit
		if coarse && low < floor {
			t.Fatalf("a client crediting %d at a time was cut to %d, under half its window and the guard's credit, %d", step, low, floor)
		}
		if !coarse && low >= floor {
			t.Fatalf("a client crediting %d at a time was held at %d, not cut under %d", step, low, floor)
		}
	}
}
