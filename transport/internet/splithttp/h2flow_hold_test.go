package splithttp

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"golang.org/x/net/http2"
)

// TestFlowHold checks when credit waits: only while it is under a quantum and
// the sender still has one.
func TestFlowHold(t *testing.T) {
	for _, tc := range []struct {
		cap  int32
		want int64
	}{{h2InitWindow, flowQuantumMin}, {flowStartWindow, flowQuantumMax}, {8 << 20, flowQuantumMax}, {160 << 10, 20 << 10}} {
		if got := quantum(tc.cap); got != tc.want {
			t.Errorf("quantum(%d) = %d, want %d", tc.cap, got, tc.want)
		}
	}
	const q = flowQuantumMax
	for _, tc := range []struct {
		rel, window int64
		want        bool
	}{
		{4 << 10, 256 << 10, true}, // small credit, sender has plenty
		{q, 256 << 10, false},      // a whole quantum goes out
		{4 << 10, q - 1, false},    // sender about to run dry
		{4 << 10, 0, false},        // sender has nothing left
		{1, q, true},
	} {
		if got := hold(tc.rel, tc.window, q); got != tc.want {
			t.Errorf("hold(%d, %d) = %v, want %v", tc.rel, tc.window, got, tc.want)
		}
	}
	if flowQuantumMax >= flowSmallCredit {
		t.Fatal("a quantum must stay below flowSmallCredit, or a governor at the other end stops seeing small steps")
	}
}

// TestFlowCreditWaitsForAQuantum returns a server's data to it as a Go client
// does, 4 KiB at a time. While the server has a quantum of window left the
// pieces wait and go out as one; once it has less, a piece goes out at once.
func TestFlowCreditWaitsForAQuantum(t *testing.T) {
	const id, piece = 1, 4 << 10
	h := newFlowHarness(t)
	h.c.down.max = flowStartWindow // the cap stays where it starts
	h.track()
	h.openStream(4 << 20)
	q := quantum(flowStartWindow)
	sent := int64(0)
	window := func() int64 { return h.toServer.streams[id] - sent }
	send := func(n int64) {
		h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, id, int(n)) })
		sent += n
	}
	read := func() int64 {
		before := h.toServer.streams[id]
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, piece) })
		return h.toServer.streams[id] - before
	}
	if window() != flowStartWindow {
		t.Fatalf("the stream opened with a window of %d, want %d", window(), flowStartWindow)
	}

	send(flowStartWindow / 2)
	updates := 0
	for returned := int64(piece); returned <= flowStartWindow/2; returned += piece {
		had := window()
		switch got := read(); {
		case got == 0:
		case got < q:
			t.Fatalf("credit of %d handed on while the server had a window of %d", got, had)
		default:
			updates++
		}
	}
	if want := int(flowStartWindow / 2 / q); updates != want {
		t.Fatalf("%d KiB of credit went out in %d pieces, want %d", flowStartWindow/2>>10, updates, want)
	}
	if owed := flowStartWindow - window(); owed >= q {
		t.Fatalf("%d of credit is still held after the client read everything", owed)
	}

	send(window() - q/2)
	if got := read(); got < piece {
		t.Fatalf("with a window of %d the server was handed %d, want the piece at once", q/2, got)
	}
}

// windowUpdates counts the WINDOW_UPDATE frames in b by stream and adds up
// what they carry.
func windowUpdates(t *testing.T, b []byte, count map[uint32]int, sum map[uint32]uint64) {
	t.Helper()
	fr := http2.NewFramer(nil, bytes.NewReader(b))
	for {
		f, err := fr.ReadFrame()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if w, ok := f.(*http2.WindowUpdateFrame); ok {
			count[w.StreamID]++
			sum[w.StreamID] += uint64(w.Increment)
		}
	}
}

// TestFlowUploadCreditNotHeld is the upload side of a server: the local
// server returns an upload's credit 4 KiB at a time, for the stream and for
// the connection, and each piece goes on to the client as it comes, also once
// the upload has stopped speeding up. That credit crosses the network, and
// its packets are what the client's kernel sees of the server's sending
// during an upload: held to quanta they were an eighth as many here, and the
// slow start threshold Linux keeps from them fell with their number.
func TestFlowUploadCreditNotHeld(t *testing.T) {
	h := newFlowHarness(t)
	t.Cleanup(func() { h.c.Close() })
	h.c.up.init = flowShownUp
	h.c.up.max = flowShownUp // the cap stays where it starts
	h.track()
	h.openStream(4 << 20)
	h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 6<<20-h2InitWindow) })
	h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, 1, 512<<10) })
	credit := func() []byte {
		return h.fromServer(func(fr *http2.Framer) {
			fr.WriteWindowUpdate(1, 4<<10)
			fr.WriteWindowUpdate(0, 4<<10)
		})
	}
	// The first of it shows the reader reads and funds the connection's floor.
	for i := 0; i < 8; i++ {
		credit()
	}
	h.c.mu.Lock()
	h.c.streams[1].up.ramped = true
	h.c.mu.Unlock()
	count, sum := map[uint32]int{}, map[uint32]uint64{}
	for i := 0; i < 32; i++ {
		windowUpdates(t, credit(), count, sum)
	}
	for _, id := range []uint32{0, 1} {
		if count[id] != 32 || sum[id] != 128<<10 {
			t.Errorf("stream %d: %d updates carrying %d bytes, want each of 32 pieces of 4 KiB at once", id, count[id], sum[id])
		}
	}
}

// TestFlowClientDownloadCreditNotHeld is the same for a governed client: the
// local client returns a download's credit 4 KiB at a time, and each piece
// goes on to the server as it comes. On a client it is the download's credit
// that crosses the network.
func TestFlowClientDownloadCreditNotHeld(t *testing.T) {
	const id, piece, pieces = 1, 4 << 10, 16
	ch := newChain(t, 0)
	ch.start()
	ch.open(id)
	sent := ch.sendAll(id)
	if sent < 2*pieces*piece {
		t.Fatalf("the server sent %d, want room for %d pieces of credit", sent, pieces)
	}
	count, sum := map[uint32]int{}, map[uint32]uint64{}
	for i := 0; i < pieces; i++ {
		if _, err := ch.cg.Write(frames(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, piece) })); err != nil {
			t.Fatal(err)
		}
		windowUpdates(t, ch.cconn.take(), count, sum)
	}
	if count[id] != pieces || sum[id] != pieces*piece {
		t.Fatalf("%d updates carrying %d bytes reached the wire, want each of %d pieces of 4 KiB at once", count[id], sum[id], pieces)
	}
}
