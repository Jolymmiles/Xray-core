package splithttp

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"
)

// connCredit sums the connection-level credit in frames read by the client.
func connCredit(t *testing.T, b []byte) int64 {
	t.Helper()
	var n int64
	fr := http2.NewFramer(nil, bytes.NewReader(b))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return n
		}
		if w, ok := f.(*http2.WindowUpdateFrame); ok && w.StreamID == 0 {
			n += int64(w.Increment)
		}
	}
}

// TestFlowUploadConnectionWindow checks the connection window the client is
// shown for uploads: Go's 1 MiB while no reader has taken anything, whatever
// the server grants, and room for the streams whose readers do take data on
// top of that once they do, never beyond what the server really granted.
func TestFlowUploadConnectionWindow(t *testing.T) {
	const granted = 6 << 20
	h := newFlowHarness(t)
	h.openStream(4 << 20)
	credit := connCredit(t, h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, granted-h2InitWindow) }))
	sent, returned := int64(0), int64(granted-h2InitWindow)
	shown := func() int64 { return h2InitWindow + credit - sent }
	if got := shown(); got != flowConnFloor {
		t.Fatalf("client shown a connection window of %d before any read, want %d", got, flowConnFloor)
	}

	const chunk = 200 << 10
	h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, 1, chunk) })
	sent += chunk
	if got := shown(); got != flowConnFloor-chunk {
		t.Fatalf("client shown %d after sending %d, want %d", got, chunk, flowConnFloor-chunk)
	}

	// The handler reads what came; its stream then may hold 4 MiB.
	credit += connCredit(t, h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(1, chunk) }))
	h.c.mu.Lock()
	h.c.streams[1].up.cap = 4 << 20
	h.c.mu.Unlock()
	credit += connCredit(t, h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, chunk) }))
	returned += chunk
	if got, want := shown(), int64(flowConnFloor+4<<20); got != want {
		t.Fatalf("client shown %d with a reader that keeps up, want %d", got, want)
	}
	if real := h2InitWindow + returned - sent; shown() > real {
		t.Fatalf("client shown %d, server accepts %d", shown(), real)
	}
}

// TestFlowSlowReaderLeavesConnectionRoom fills eight streams whose readers
// are slow to their caps, together more than Go's 1 MiB: a new stream must
// still get connection credit, or slow uploads would hold up every request
// behind them on the connection.
func TestFlowSlowReaderLeavesConnectionRoom(t *testing.T) {
	h := newFlowHarness(t)
	h.openStream(4 << 20)
	credit := connCredit(t, h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 6<<20-h2InitWindow) }))
	var sent, held int64
	for id := uint32(1); id <= 15; id += 2 {
		if id > 1 {
			h.fromClient(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x82}, EndHeaders: true})
			})
		}
		// The reader takes a little, then stalls with its stream full.
		h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, id, 16<<10) })
		sent += 16 << 10
		credit += connCredit(t, h.fromServer(func(fr *http2.Framer) {
			fr.WriteWindowUpdate(id, 16<<10)
			fr.WriteWindowUpdate(0, 16<<10)
		}))
		h.c.mu.Lock()
		full := int64(h.c.streams[id].up.cap)
		h.c.mu.Unlock()
		h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, id, int(full)) })
		sent += full
		held += full
	}
	credit += connCredit(t, h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 1) }))

	if room := h2InitWindow + credit - sent; room < flowConnFloor/2 {
		t.Fatalf("slow readers holding %d leave %d of connection window for new streams", held, room)
	}
}
