package splithttp

import (
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
