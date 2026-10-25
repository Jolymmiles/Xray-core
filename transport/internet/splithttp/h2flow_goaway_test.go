package splithttp

import (
	"bytes"
	"testing"

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
