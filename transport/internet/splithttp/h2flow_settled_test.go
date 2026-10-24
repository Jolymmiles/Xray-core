package splithttp

import (
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// vouchedPath makes c take the kernel's word for a round trip of 50 ms, as a
// connection on Linux does once TCP_INFO agrees with its PINGs: the state in
// which a window may follow the path model. The kernel is not asked again
// for the length of a test.
func vouchedPath(c *flowConn) {
	const rtt = 50 * time.Millisecond
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tcp, c.kAt, c.kOK = fakeRawConn{}, time.Now().Add(time.Hour), true
	c.kstat = tcpStats{rtt: rtt, minRTT: rtt}
	c.rttBase = rtt
}

// lowRoundBehind puts w where a stream is after one round trip that read low
// at its start: ramped, since that round was not above the one before, with
// steady flat rounds since, a small round to go by, and a round trip that
// ends with the next credit.
func lowRoundBehind(w *flowWindow, steady int) {
	w.ramped, w.flat, w.steady = true, steady, steady
	w.prev, w.measured = 8<<10, true
	w.mark, w.markBase = time.Now().Add(-time.Second), w.returned
}

// TestFlowUploadFollowsModelOnceSettled is a server whose kernel vouches for
// the path, and an upload one low round into its start. Its window stays
// where it started: the path model, which would have that one small round to
// go by, is not asked yet. After a second such round it is, and the window
// goes where the model puts it.
func TestFlowUploadFollowsModelOnceSettled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flat    int
		modeled bool
	}{
		{"one flat round", flowSettledRounds - 1, false},
		{"settled", flowSettledRounds, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const id = 1
			h := newFlowHarness(t)
			t.Cleanup(func() { h.c.Close() })
			h.track()
			h.openStream(4 << 20)
			// Connection credit, so the client may send the upload.
			h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 8<<20) })
			h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, id, 200<<10) })
			vouchedPath(h.c)
			h.c.mu.Lock()
			s := h.c.streams[id]
			start := s.up.cap
			lowRoundBehind(&s.up, tc.flat)
			h.c.mu.Unlock()
			if start != flowStartWindow {
				t.Fatalf("the upload starts with a cap of %d, want %d", start, flowStartWindow)
			}
			h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, 4<<10) })
			h.c.mu.Lock()
			got, floor := s.up.cap, h.c.up.init
			h.c.mu.Unlock()
			if tc.modeled && got != floor {
				t.Fatalf("a settled upload has a cap of %d, want the %d the path model gives a reader this slow", got, floor)
			}
			if !tc.modeled && got != start {
				t.Fatalf("one low round took the cap from %d to %d: the window follows the path model before its reader has settled", start, got)
			}
		})
	}
}

// TestFlowClientDownloadFollowsModelOnceSettled is the same for a governed
// client's download, the window that follows the model on that side.
func TestFlowClientDownloadFollowsModelOnceSettled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flat    int
		modeled bool
	}{
		{"one flat round", flowSettledRounds - 1, false},
		{"settled", flowSettledRounds, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const id = 1
			ch := newChain(t, 0)
			ch.start()
			ch.open(id)
			if sent := ch.sendAll(id); sent == 0 {
				t.Fatal("the server sent nothing")
			}
			vouchedPath(ch.cg)
			ch.cg.mu.Lock()
			// The model is for a server that does not govern: the chain's
			// does, and the client would leave the window to it.
			ch.cg.peerGoverned = false
			s := ch.cg.streams[id]
			start := s.down.cap
			lowRoundBehind(&s.down, tc.flat)
			ch.cg.mu.Unlock()
			if _, err := ch.cg.Write(frames(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, 4<<10) })); err != nil {
				t.Fatal(err)
			}
			ch.cg.mu.Lock()
			got, floor := s.down.cap, ch.cg.down.init
			ch.cg.mu.Unlock()
			if tc.modeled && got != floor {
				t.Fatalf("a settled download has a cap of %d, want the %d the path model gives a reader this slow", got, floor)
			}
			if !tc.modeled && got < start {
				t.Fatalf("one low round took the cap from %d to %d: the window follows the path model before its reader has settled", start, got)
			}
		})
	}
}
