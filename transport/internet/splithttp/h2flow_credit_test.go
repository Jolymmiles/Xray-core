package splithttp

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"golang.org/x/net/http2"
)

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
// during an upload. Held back until 16 to 32 KiB had gathered they were an
// eighth as many here, and the slow start threshold Linux keeps from them
// fell with their number: the download that followed started slower.
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

// TestFlowDownloadCreditNotHeld is the download side of a server: the client
// returns a download's credit 4 KiB at a time, and the local server is
// handed each piece as it comes. Holding it back saved no processor time
// that a stand could show, so nothing holds credit any more.
func TestFlowDownloadCreditNotHeld(t *testing.T) {
	const id, piece, pieces = 1, 4 << 10, 16
	h := newFlowHarness(t)
	t.Cleanup(func() { h.c.Close() })
	h.c.down.max = flowStartWindow // the cap stays where it starts
	h.track()
	h.openStream(4 << 20)
	h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, id, flowStartWindow/2) })
	for i := 0; i < pieces; i++ {
		before := h.toServer.streams[id]
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, piece) })
		if got := h.toServer.streams[id] - before; got != piece {
			t.Fatalf("piece %d: the server was handed %d of credit, want the %d the client returned", i, got, piece)
		}
	}
}
