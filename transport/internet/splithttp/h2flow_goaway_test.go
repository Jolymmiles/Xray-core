package splithttp

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestFlowGoAwayDropsStreamsPastLast has the server send GOAWAY naming
// stream 1 as its last, with downloads open on 1 and 3: stream 3 is one the
// server will not take up, and the governor forgets it as the stacks do,
// where it held its share of the client's credit and a stream's slot until
// the connection closed. Stream 1 stays, and the GOAWAY reaches the client as
// it was sent.
func TestFlowGoAwayDropsStreamsPastLast(t *testing.T) {
	h := newFlowHarness(t)
	t.Cleanup(func() { h.c.Close() })
	h.openRequest(1)
	h.openRequest(3)
	goAway := frames(func(fr *http2.Framer) { fr.WriteGoAway(1, http2.ErrCodeNo, []byte("bye")) })
	got, err := h.fromServerRaw(goAway)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, goAway) {
		t.Fatalf("the GOAWAY reached the client as %x, sent %x", got, goAway)
	}
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if h.c.streams[3] != nil || h.c.downOpen != 1 {
		t.Fatalf("after GOAWAY(last=1) stream 3 tracked: %v, %d downloads open", h.c.streams[3] != nil, h.c.downOpen)
	}
	if h.c.streams[1] == nil {
		t.Fatal("stream 1, the last the server takes up, was dropped")
	}
}

// TestFlowGoAwayLaterStreamNotTaken has the server send GOAWAY naming stream 1
// as its last, and then the client's HEADERS for stream 3, sent before it saw
// the GOAWAY, arrive: the server takes up no stream past its last, and the
// governor neither tracks stream 3 nor credits it. Before, it did both, and
// the credit counted against the send window of the streams still draining.
func TestFlowGoAwayLaterStreamNotTaken(t *testing.T) {
	h := newFlowHarnessWindow(t, flowServerSendWindow)
	t.Cleanup(func() { h.c.Close() })
	h.track()
	h.openStream(4 << 20) // opens stream 1
	h.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: flowServerReceiveWindow})
	})
	now := time.Now()
	h.c.mu.Lock()
	h.c.downLearned.note(now, h.c.down.init, flowServerSendWindow)
	h.c.upLearned.note(now, h.c.up.init, 2<<20)
	h.c.mu.Unlock()

	// Server sends GOAWAY(last=1) while stream 1 is still active.
	goAway := frames(func(fr *http2.Framer) { fr.WriteGoAway(1, http2.ErrCodeNo, nil) })
	if _, err := h.fromServerRaw(goAway); err != nil {
		t.Fatal(err)
	}

	// Client's in-flight HEADERS for stream 3 arrives at flowReader after GOAWAY(last=1).
	h.conn.take()
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: []byte{0x82}, EndHeaders: true})
	})
	h.sync()
	toClient := h.conn.take()

	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	t.Logf("after post-GOAWAY HEADERS(3): streams[3]=%v, downOpen=%d, downOpenForwarded=%d, clientHolds=%d (sendWindow=%d), toClient=%x",
		h.c.streams[3] != nil, h.c.downOpen, h.c.downOpenForwarded, h.c.clientHolds(), h.c.sendWindow, toClient)
	if h.c.streams[3] != nil || h.c.downOpen != 1 || len(toClient) != 0 {
		t.Fatalf("post-GOAWAY(last=1) in-flight stream 3 was tracked, leaked, and credited: streams[3]=%v, downOpen=%d, clientHolds=%d/%d, toClient=%x",
			h.c.streams[3] != nil, h.c.downOpen, h.c.clientHolds(), h.c.sendWindow, toClient)
	}
}
