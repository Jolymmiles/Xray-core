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
