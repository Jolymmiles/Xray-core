package splithttp

import (
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// queuedDownload is a server with one download whose reader takes all it is
// sent, on a path whose round trip stands at 500 ms over an empty 50 ms: a
// queue the server cuts against. The cap is 1 MiB.
func queuedDownload(t *testing.T) (h *flowHarness, s *flowStream) {
	t.Helper()
	const id = 1
	h = newFlowHarness(t)
	t.Cleanup(func() { h.c.Close() })
	h.track()
	h.openStream(4 << 20)
	h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, id, 200<<10) })
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	h.c.tcp, h.c.kAt, h.c.kOK = fakeRawConn{}, time.Now().Add(time.Hour), true
	h.c.kstat = tcpStats{rtt: 500 * time.Millisecond, minRTT: 50 * time.Millisecond}
	h.c.rttBase = 50 * time.Millisecond
	s = h.c.streams[id]
	s.down.cap = 1 << 20
	s.down.mark, s.down.markBase = time.Now(), s.down.returned
	return h, s
}

// credit returns 4 KiB of the download's credit and gives the cap after it.
func credit(h *flowHarness, s *flowStream) int32 {
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(1, 4<<10) })
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	return s.down.cap
}

// TestFlowNoQueueCuts is a download against a standing queue on a server
// that leaves the queue to TCP: neither pi nor the cut at a long queue takes
// its cap down, where the same server without the setting cuts it.
func TestFlowNoQueueCuts(t *testing.T) {
	for _, noCuts := range []bool{false, true} {
		h, s := queuedDownload(t)
		h.c.mu.Lock()
		h.c.noQueueCuts = noCuts
		h.c.mu.Unlock()
		got := credit(h, s)
		if cut := got < 1<<20; cut == noCuts {
			t.Fatalf("noQueueCuts %v: the cap went from 1 MiB to %d", noCuts, got)
		}
	}
}

// TestFlowNoQueueCutsStopsPI is a queue of 60 ms over an empty 50 ms, short
// of the cut at a long queue but well over pi's setpoint, on a download pi
// governs: a client that returns credit in small steps, a reader that has
// settled, a round trip measured. pi cuts it, unless the server leaves the
// queue to TCP.
func TestFlowNoQueueCutsStopsPI(t *testing.T) {
	for _, noCuts := range []bool{false, true} {
		h, s := queuedDownload(t)
		h.c.mu.Lock()
		h.c.noQueueCuts, h.c.incremental = noCuts, true
		h.c.kstat.rtt = 110 * time.Millisecond
		s.down.flat = flowFullRounds
		s.down.mark = time.Now().Add(-200 * time.Millisecond)
		h.c.mu.Unlock()
		got := credit(h, s)
		if cut := got < 1<<20; cut == noCuts {
			t.Fatalf("noQueueCuts %v: pi took the cap from 1 MiB to %d", noCuts, got)
		}
	}
}

// TestFlowPIForgetsRoundTripOutside is a download pi does not govern for a
// round, here one whose client credits in large steps: the round trip pi saw
// last is dropped, so that pi, when the stream comes back to it, does not
// take the change since then for one round's.
func TestFlowPIForgetsRoundTripOutside(t *testing.T) {
	h, s := queuedDownload(t)
	h.c.mu.Lock()
	s.down.piRTT = 100 * time.Millisecond
	h.c.mu.Unlock()
	credit(h, s)
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if s.down.piRTT != 0 {
		t.Fatalf("pi's round trip %v kept outside pi", s.down.piRTT)
	}
}
