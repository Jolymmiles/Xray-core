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

// rampStates are the two states of a stream's window that credit must not
// depend on: its reader still speeding up, as every stream starts, and no
// longer.
var rampStates = []struct {
	name   string
	ramped bool
}{
	{"speeding up", false},
	{"no longer speeding up", true},
}

// owesNothing fails the test if the governor still has upload credit for the
// client that it could hand on now, for the stream or for the connection:
// credit that goes on a round late adds up to the right sums from then on.
func owesNothing(t *testing.T, h *flowHarness, id uint32) {
	t.Helper()
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if rel := h.c.upRelease(h.c.streams[id]); rel > 0 {
		t.Fatalf("%d bytes of stream credit are due and were not handed on", rel)
	}
	if rel := h.c.upConnRelease(); rel > 0 {
		t.Fatalf("%d bytes of connection credit are due and were not handed on", rel)
	}
}

// TestFlowUploadCreditNotHeld is the upload side of a server. The local
// server returns an upload's credit 4 KiB at a time, and the client is handed
// each piece as it comes, for the stream and for the connection, whether or
// not the upload still speeds up. Go's server returns the connection's credit
// before the stream's, and the governor then hands it on where it reads that
// frame; returned after the stream's it goes on with the stream's. Both ways
// are run. Credit quanta held such pieces back until 16 to 32 KiB had
// gathered: 4 WINDOW_UPDATE frames for these 32, on either stream.
func TestFlowUploadCreditNotHeld(t *testing.T) {
	const id, piece, pieces = 1, 4 << 10, 32
	for _, order := range []struct {
		name  string
		first uint32
	}{
		{"connection credit first", 0},
		{"stream credit first", id},
	} {
		for _, state := range rampStates {
			t.Run(order.name+", "+state.name, func(t *testing.T) {
				h := newFlowHarness(t)
				t.Cleanup(func() { h.c.Close() })
				h.c.up.init = flowShownUp
				h.c.up.max = flowShownUp // the cap stays where it starts
				h.track()
				h.openStream(4 << 20)
				h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 6<<20-h2InitWindow) })
				h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, id, 512<<10) })
				if h.c.streams[id].up.ramped {
					t.Fatal("a new upload counts as one that has stopped speeding up")
				}
				credit := func() []byte {
					return h.fromServer(func(fr *http2.Framer) {
						fr.WriteWindowUpdate(order.first, piece)
						fr.WriteWindowUpdate(id-order.first, piece)
					})
				}
				// The first of it shows the reader reads and funds the connection's floor.
				for i := 0; i < 8; i++ {
					credit()
				}
				h.c.mu.Lock()
				h.c.streams[id].up.ramped = state.ramped
				h.c.mu.Unlock()
				for i := 0; i < pieces; i++ {
					count, sum := map[uint32]int{}, map[uint32]uint64{}
					windowUpdates(t, credit(), count, sum)
					for _, stream := range []uint32{0, id} {
						if sum[stream] != piece {
							t.Fatalf("piece %d, stream %d: %d updates carrying %d bytes went on, want the %d the server returned", i, stream, count[stream], sum[stream], piece)
						}
					}
				}
				owesNothing(t, h, id)
				if got := h.c.streams[id].up.ramped; got != state.ramped {
					t.Fatalf("the upload ended the test with ramped %v, want %v", got, state.ramped)
				}
			})
		}
	}
}

// TestFlowUploadConnectionCreditFollowsCap covers the connection credit that
// goes on with a stream's. Until an upload's first round trip is measured its
// cap opens with every credit, and the room its stream has on the connection
// opens with it: that credit is due where the stream's WINDOW_UPDATE is read,
// after the connection's own has been handed on. Each piece of 4 KiB here
// opens the cap by 8 KiB. The two frames are fed one at a time, so that each
// answers for what it frees: credit that left a round late would still add
// up over the two.
func TestFlowUploadConnectionCreditFollowsCap(t *testing.T) {
	const id, piece, pieces = 1, 4 << 10, 16
	for _, state := range rampStates {
		t.Run(state.name, func(t *testing.T) {
			h := newFlowHarness(t)
			t.Cleanup(func() { h.c.Close() })
			h.track()
			h.openStream(4 << 20)
			h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 6<<20-h2InitWindow) })
			// Under the cap a stream starts with, so the cap is what the stream
			// counts for on the connection, and more than is returned below.
			h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, id, 200<<10) })
			credit := func(stream uint32) map[uint32]uint64 {
				count, sum := map[uint32]int{}, map[uint32]uint64{}
				windowUpdates(t, h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(stream, piece) }), count, sum)
				return sum
			}
			// Enough for the cap to start opening with every piece.
			for i := 0; i < 32; i++ {
				credit(0)
				credit(id)
			}
			owesNothing(t, h, id)
			h.c.mu.Lock()
			h.c.streams[id].up.ramped = state.ramped
			h.c.mu.Unlock()
			for i := 0; i < pieces; i++ {
				if sum := credit(0); sum[0] != piece || sum[id] != 0 {
					t.Fatalf("piece %d, the connection's frame: %d bytes of connection credit and %d of stream credit went on, want its own %d and none", i, sum[0], sum[id], piece)
				}
				before := h.c.streams[id].up.cap
				sum := credit(id)
				opened := uint64(h.c.streams[id].up.cap - before)
				if opened == 0 {
					t.Fatalf("piece %d: the cap stayed at %d, so no connection credit followed it", i, before)
				}
				if sum[0] != opened {
					t.Fatalf("piece %d, the stream's frame: %d bytes of connection credit went on, want the %d the cap opened by", i, sum[0], opened)
				}
			}
			owesNothing(t, h, id)
		})
	}
}

// TestFlowEndedUploadConnectionCreditNotHeld returns connection credit on its
// own, as Go's server does for a request whose body has ended, every
// packet-up POST among them: no stream credit follows that could carry it.
func TestFlowEndedUploadConnectionCreditNotHeld(t *testing.T) {
	h := newFlowHarness(t)
	t.Cleanup(func() { h.c.Close() })
	h.c.up.init, h.c.up.max = flowShownUp, flowShownUp
	h.track()
	h.openStream(4 << 20)
	h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 6<<20-h2InitWindow) })
	h.fromClient(func(fr *http2.Framer) { fr.WriteData(1, true, make([]byte, 4<<10)) })
	count, sum := map[uint32]int{}, map[uint32]uint64{}
	windowUpdates(t, h.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 4<<10) }), count, sum)
	if count[0] != 1 || sum[0] != 4<<10 {
		t.Fatalf("ended upload: %d connection updates carrying %d, want the 4096 at once", count[0], sum[0])
	}
}

// TestFlowDownloadCreditNotHeld is the download side of a server: the client
// returns a download's credit 4 KiB at a time, and the local server is
// handed each piece as it comes, whether or not the download still speeds
// up.
func TestFlowDownloadCreditNotHeld(t *testing.T) {
	const id, piece, pieces = 1, 4 << 10, 16
	for _, state := range rampStates {
		t.Run(state.name, func(t *testing.T) {
			h := newFlowHarness(t)
			t.Cleanup(func() { h.c.Close() })
			h.c.down.max = flowStartWindow // the cap stays where it starts
			h.track()
			h.openStream(4 << 20)
			h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, id, flowStartWindow/2) })
			if h.c.streams[id].down.ramped {
				t.Fatal("a new download counts as one that has stopped speeding up")
			}
			h.c.mu.Lock()
			h.c.streams[id].down.ramped = state.ramped
			h.c.mu.Unlock()
			for i := 0; i < pieces; i++ {
				before := h.toServer.streams[id]
				h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, piece) })
				if got := h.toServer.streams[id] - before; got != piece {
					t.Fatalf("piece %d: the server was handed %d of credit, want the %d the client returned", i, got, piece)
				}
			}
			if got := h.c.streams[id].down.ramped; got != state.ramped {
				t.Fatalf("the download ended the test with ramped %v, want %v", got, state.ramped)
			}
		})
	}
}

// TestFlowClientDownloadCreditNotHeld is the same for a governed client: the
// local client returns a download's credit 4 KiB at a time, and each piece
// goes on to the server as it comes. On a client it is the download's credit
// that crosses the network.
func TestFlowClientDownloadCreditNotHeld(t *testing.T) {
	const id, piece, pieces = 1, 4 << 10, 16
	for _, state := range rampStates {
		t.Run(state.name, func(t *testing.T) {
			ch := newChain(t, 0)
			ch.start()
			ch.open(id)
			sent := ch.sendAll(id)
			if sent < 2*pieces*piece {
				t.Fatalf("the server sent %d, want room for %d pieces of credit", sent, pieces)
			}
			ch.cg.mu.Lock()
			ch.cg.streams[id].down.ramped = state.ramped
			ch.cg.mu.Unlock()
			for i := 0; i < pieces; i++ {
				if _, err := ch.cg.Write(frames(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, piece) })); err != nil {
					t.Fatal(err)
				}
				count, sum := map[uint32]int{}, map[uint32]uint64{}
				windowUpdates(t, ch.cconn.take(), count, sum)
				if sum[id] != piece {
					t.Fatalf("piece %d: %d updates carrying %d bytes reached the wire, want the %d the client returned", i, count[id], sum[id], piece)
				}
			}
			ch.cg.mu.Lock()
			got := ch.cg.streams[id].down.ramped
			ch.cg.mu.Unlock()
			if got != state.ramped {
				t.Fatalf("the download ended the test with ramped %v, want %v", got, state.ramped)
			}
		})
	}
}
