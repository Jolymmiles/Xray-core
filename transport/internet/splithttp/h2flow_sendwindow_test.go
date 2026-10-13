package splithttp

import (
	"errors"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// openStreams starts a governed server connection whose client grants
// clientWindow per stream, opens n request streams on it and returns the
// harness; h.toServer then holds what the server may send on each.
func openStreams(t *testing.T, sendWindow int64, clientWindow uint32, n int) *flowHarness {
	t.Helper()
	h := newFlowHarness(t)
	h.c.sendWindow = sendWindow
	h.track()
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: clientWindow})
	})
	h.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6 << 20})
	})
	for i := 0; i < n; i++ {
		h.fromClient(func(fr *http2.Framer) {
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: uint32(2*i + 1), BlockFragment: []byte{0x82}, EndHeaders: true})
		})
	}
	return h
}

// granted sums what the server may send, and counts the streams that have
// only the window every stream has.
func granted(h *flowHarness) (total int64, atDefault int) {
	for _, w := range h.toServer.streams {
		total += w
		if w == flowShownLimited {
			atDefault++
		}
	}
	return total, atDefault
}

// TestFlowSendWindowBoundsManyStreams opens forty streams at once. Without a
// limit each starts with flowStartWindow, 10 MiB in all that the client must
// be ready to hold. With the limit the streams share it; those opened once it
// is used up keep the window every stream has, which cannot be withheld, and
// nothing more.
func TestFlowSendWindowBoundsManyStreams(t *testing.T) {
	const n = 40
	total, _ := granted(openStreams(t, 0, 4<<20, n))
	if total != n*flowStartWindow {
		t.Fatalf("without a limit the server may send %d on %d streams, want %d", total, n, n*flowStartWindow)
	}

	h := openStreams(t, flowServerSendWindow, 4<<20, n)
	total, atDefault := granted(h)
	if atDefault == 0 || atDefault == n {
		t.Fatalf("%d of %d streams have only the window every stream has", atDefault, n)
	}
	// The streams that got more than the default fill the limit and stop.
	above := total - int64(atDefault)*flowShownLimited
	if above > flowServerSendWindow || above < flowServerSendWindow-flowStartWindow {
		t.Fatalf("streams above the default window may send %d, the limit is %d", above, flowServerSendWindow)
	}
	for id, w := range h.toServer.streams {
		if w < flowShownLimited {
			t.Fatalf("stream %d was left with a window of %d, below what every stream has", id, w)
		}
	}
	t.Logf("%d streams: %d in all with the limit, %d without", n, total, n*flowStartWindow)
}

// TestFlowSendWindowIgnoresClientWindow gives the same streams to a client
// that grants 16 MiB per stream. The limit is what was configured, not what
// the client announces: a client with a governor of its own announces the
// protocol default whatever its window, so the announcement says nothing.
func TestFlowSendWindowIgnoresClientWindow(t *testing.T) {
	const n = 40
	with4, _ := granted(openStreams(t, flowServerSendWindow, 4<<20, n))
	with16, _ := granted(openStreams(t, flowServerSendWindow, 16<<20, n))
	if with16 != with4 {
		t.Fatalf("server may send %d to a client granting 16 MiB a stream and %d to one granting 4 MiB", with16, with4)
	}
}

// TestFlowSendWindowBelowClientWindow sets a limit under the 4 MiB a Go
// client grants one stream: it holds, for forty streams and for one.
func TestFlowSendWindowBelowClientWindow(t *testing.T) {
	const limit = 1 << 20
	h := openStreams(t, limit, 4<<20, 40)
	total, atLeast := granted(h)
	if above := total - int64(atLeast)*flowShownLimited; above > limit || above < limit-flowStartWindow {
		t.Fatalf("streams above the least window may send %d, the limit is %d", above, limit)
	}
	// One stream alone grows as its reader takes, but not past the limit.
	h = openStreams(t, limit, 4<<20, 1)
	sent := int64(0)
	for round := 0; round < 64; round++ {
		w := h.toServer.streams[1] - sent
		if w > limit {
			t.Fatalf("round %d: one stream may be sent %d at once, the limit is %d", round, w, limit)
		}
		h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, 1, int(w)) })
		sent += w
		for left := w; left > 0; left -= min(left, 16<<10) {
			h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(1, uint32(min(left, 16<<10))) })
		}
	}
	if sent < 8*limit {
		t.Fatalf("one stream was sent %d in 64 rounds: the limit stops it instead of pacing it", sent)
	}
}

// TestFlowSendWindowIsReturned fills the limit with forty downloads, lets the
// server end eight of them, and has only the last one read. A stream is
// looked at when its own client returns credit, so the reader that reads is
// the one that gets the room: it comes to its opening window with its first
// credit and keeps it, whatever the streams before it that nobody reads.
func TestFlowSendWindowIsReturned(t *testing.T) {
	const n = 40
	h := openStreams(t, flowServerSendWindow, 4<<20, n)
	t.Cleanup(func() { h.c.Close() })
	last := uint32(2*n - 1)
	if got := h.toServer.streams[last]; got != flowShownLimited {
		t.Fatalf("the last stream opened with %d, want %d once the limit is used up", got, flowShownLimited)
	}
	for id := uint32(1); id <= 15; id += 2 {
		w := int(h.toServer.streams[id])
		h.fromServer(func(fr *http2.Framer) {
			writeDataSplit(fr, id, w)
			fr.WriteData(id, true, nil)
		})
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, uint32(w)) })
		delete(h.toServer.streams, id)
	}
	sent := int64(0)
	for turn := 0; turn < 64; turn++ {
		window := h.toServer.streams[last] - sent
		if want := int64(flowShownLimited); turn > 0 {
			want = openingWindow(flowServerSendWindow)
			if window < want {
				t.Fatalf("turn %d: the reading stream may send %d, want at least %d", turn, window, want)
			}
		} else if window != want {
			t.Fatalf("turn 0: the reading stream may send %d, want %d", window, want)
		}
		h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, last, int(window)) })
		sent += window
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(last, uint32(window)) })
	}
	total, _ := granted(h)
	if above := total - sent - int64(n-9)*flowShownLimited; above > flowServerSendWindow {
		t.Fatalf("the reading stream and the limit's own streams may send %d more, the limit is %d", above, flowServerSendWindow)
	}
}

// finishedRounds opens downloads in rounds of twenty on h, enough to use up
// the default limit in one. The server sends each all it may and ends it,
// and the client reads nothing. It returns what each round was sent.
func finishedRounds(h *flowHarness, rounds int) (sent []int64) {
	next := uint32(1)
	for id := range h.toServer.streams {
		next = max(next, id+2)
	}
	for ; rounds > 0; rounds-- {
		var ids []uint32
		for i := 0; i < 20; i++ {
			ids = append(ids, next)
			id := next
			next += 2
			h.fromClient(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x82}, EndHeaders: true, EndStream: true})
			})
		}
		total := int64(0)
		for _, id := range ids {
			w := h.toServer.streams[id]
			h.fromServer(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x88}, EndHeaders: true})
				writeDataSplit(fr, id, int(w))
				fr.WriteData(id, true, nil)
			})
			total += w
		}
		sent = append(sent, total)
	}
	return sent
}

// goClientStart is how a Go client opens a connection and shows that it
// returns connection credit as it reads: it raises the connection window to
// 1 GiB, and after one small download returns its bytes to the connection.
func goClientStart(t *testing.T, h *flowHarness) {
	t.Helper()
	const first = 8 << 10
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteWindowUpdate(0, 1<<30-h2InitWindow)
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}, EndHeaders: true, EndStream: true})
	})
	h.fromServer(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x88}, EndHeaders: true})
		fr.WriteData(1, true, make([]byte, first))
	})
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, first) })
	if !h.c.downConnSmall || h.c.clientHolds() != 0 {
		t.Fatalf("after one download read to the end: small connection credit seen %v, client holds %d, want true and 0",
			h.c.downConnSmall, h.c.clientHolds())
	}
}

// TestFlowSendWindowCountsFinishedDownloads has downloads the server ends and
// the client does not read: their data is still the client's to hold, and
// only the connection's credit tells. Once the limit is used up a new stream
// has the window every stream has and no more, until the client returns
// connection credit for what it read.
func TestFlowSendWindowCountsFinishedDownloads(t *testing.T) {
	h := openStreams(t, flowServerSendWindow, 4<<20, 0)
	goClientStart(t, h)
	sent := finishedRounds(h, 2)
	if sent[0] != flowServerSendWindow {
		t.Fatalf("the first twenty downloads were sent %d, want the limit %d", sent[0], flowServerSendWindow)
	}
	if sent[1] != 20*flowShownLimited {
		t.Fatalf("with %d unread the next twenty downloads were sent %d, want that window each, %d", sent[0], sent[1], 20*flowShownLimited)
	}
	// The client reads it all, 16 KiB at a time.
	for left := sent[0] + sent[1]; left > 0; left -= min(left, 16<<10) {
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, uint32(min(left, 16<<10))) })
	}
	if again := finishedRounds(h, 1); again[0] != flowServerSendWindow {
		t.Fatalf("once the client had read everything twenty downloads were sent %d, want %d", again[0], flowServerSendWindow)
	}
}

// TestFlowSendWindowWithoutConnectionCredit is the same on a client that has
// not returned connection credit in small steps: it may be one that returns
// it at half of a large window, which would look as if it held that half for
// good. The connection's count is not used for it, and ended downloads are
// outside the limit.
func TestFlowSendWindowWithoutConnectionCredit(t *testing.T) {
	h := openStreams(t, flowServerSendWindow, 4<<20, 0)
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 15<<20) })
	for n, sent := range finishedRounds(h, 2) {
		if sent != flowServerSendWindow {
			t.Fatalf("round %d: twenty downloads were sent %d, want the limit %d", n+1, sent, flowServerSendWindow)
		}
	}
	// Half of its window read, it returns that at once.
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 7<<20) })
	if h.c.downConnSmall {
		t.Fatal("a 7 MiB connection credit was taken for a small step")
	}
}

// TestFlowSendWindowCreditFollowsData is the opening of a download on a
// server with a send window. The stack is shown one frame, not 65535, and
// what it is shown less is forwarded only behind data it has sent: a stream
// opens with that much less, so that the credit the stack has not used is
// what it was before, and comes to its whole cap once data moves.
func TestFlowSendWindowCreditFollowsData(t *testing.T) {
	h := newFlowHarnessWindow(t, flowServerSendWindow)
	t.Cleanup(func() { h.c.Close() })
	h.c.down.max = flowStartWindow // the cap stays where it starts
	h.track()
	h.openStream(4 << 20)
	if got, want := h.toServer.streams[1], openingWindow(flowServerSendWindow); got != want {
		t.Fatalf("the stream opened with %d, want %d", got, want)
	}
	if unused := h.c.streams[1].downForwarded; unused != flowStartWindow-flowShownFull {
		t.Fatalf("%d forwarded before any data, want %d as with %d shown", unused, flowStartWindow-flowShownFull, flowShownFull)
	}
	// The server sends all it may; the client reads it 16 KiB at a time and
	// the server sends again whatever that brings.
	sent, most := int64(0), int64(0)
	send := func() {
		if w := h.toServer.streams[1] - sent; w > 0 {
			h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, 1, int(w)) })
			sent += w
		}
	}
	send()
	for read := int64(0); read < 4<<20; read += 16 << 10 {
		h.fromClient(func(fr *http2.Framer) {
			fr.WriteWindowUpdate(1, 16<<10)
			fr.WriteWindowUpdate(0, 16<<10)
		})
		send()
		most = max(most, sent-read-16<<10)
		if unused := h.c.streams[1].downForwarded - h.c.streams[1].downSent; unused > flowStartWindow-flowShownFull {
			t.Fatalf("after %d read the stack has %d forwarded and not sent, more than the %d of a stack shown %d", read, unused, flowStartWindow-flowShownFull, flowShownFull)
		}
	}
	if most < flowStartWindow-32<<10 {
		t.Fatalf("the client held at most %d of a cap of %d: the window never opened", most, flowStartWindow)
	}
}

// TestFlowSendWindowLoweringUnderForwarded fixes what the send window leaves
// as it was: a client's initial window lowered under what the stack has been
// forwarded cannot be passed on, and the connection is given up, with the
// send window as without. That the stack has sent all it was forwarded does
// not change it.
func TestFlowSendWindowLoweringUnderForwarded(t *testing.T) {
	for _, lowered := range []uint32{100000, 65536, 65535, 60000} {
		eachSendWindow(t, func(t *testing.T, sendWindow int64) {
			h := newFlowHarnessWindow(t, sendWindow)
			t.Cleanup(func() { h.c.Close() })
			h.track()
			h.openStream(4 << 20)
			sent := h.toServer.streams[1]
			h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, 1, int(sent)) })
			h.fromClient(func(fr *http2.Framer) {
				fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: lowered})
			})
			if h.readErr == nil || !h.c.isBroken() {
				t.Fatalf("a lowering to %d under the %d forwarded was passed on", lowered, h.c.streams[1].downForwarded)
			}
		})
	}
}

// TestFlowSendWindowSettingsWithoutWindow sends a SETTINGS frame that carries
// no initial window between the opening of a download and a lowering of the
// window that can be passed on. Such a frame changes nothing about what the
// stack was shown: taking it for a client that announces no window let the
// next credit forward the stack what it had been shown less, and the lowering
// then closed the connection.
func TestFlowSendWindowSettingsWithoutWindow(t *testing.T) {
	for _, other := range []bool{false, true} {
		t.Run(map[bool]string{false: "no other SETTINGS", true: "SETTINGS without an initial window first"}[other], func(t *testing.T) {
			h := openStreams(t, flowServerSendWindow, 4<<20, 1)
			t.Cleanup(func() { h.c.Close() })
			if other {
				h.fromClient(func(fr *http2.Framer) {
					fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
				})
				h.fromClient(func(fr *http2.Framer) { fr.WriteSettings() })
			}
			h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, 1, 4096) })
			h.fromClient(func(fr *http2.Framer) {
				fr.WriteWindowUpdate(1, 4096)
				fr.WriteWindowUpdate(0, 4096)
			})
			if !h.c.shownLimited || h.c.clientShown != flowShownLimited {
				t.Fatalf("the stack is shown %d, limited %v; want %d and true", h.c.clientShown, h.c.shownLimited, flowShownLimited)
			}
			h.fromClient(func(fr *http2.Framer) {
				fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 200000})
			})
			if h.readErr != nil || h.c.isBroken() {
				t.Fatalf("a lowering to 200000 closed the connection: %v", h.readErr)
			}
		})
	}
}

// nothingShown brings a connection to a full limit with the stack shown
// nothing. An idle stream holds credit it has not used; downloads the server
// has ended and the client has not read fill the rest of the limit; the
// client lowers its initial window to just what the idle stream was
// forwarded. It returns the harness and what lies unread.
func nothingShown(t *testing.T) (h *flowHarness, unread int64) {
	t.Helper()
	const limit = 1 << 20
	h = openStreams(t, limit, 4<<20, 0)
	t.Cleanup(func() { h.c.Close() })
	goClientStart(t, h)
	h.openRequest(3) // stays idle
	idle := h.c.streams[3].downForwarded
	for id := uint32(5); id <= 15; id += 2 {
		h.openRequest(id)
		n := h.toServer.streams[id]
		h.fromServer(func(fr *http2.Framer) {
			writeDataSplit(fr, id, int(n))
			fr.WriteData(id, true, nil)
		})
		unread += n
	}
	// One more download opens at the full limit: it has its frame, shown.
	h.openRequest(waitingStream)
	if got := h.toServer.streams[waitingStream]; got != flowShownLimited {
		t.Fatalf("a stream opened at the full limit with %d, want a frame, %d", got, flowShownLimited)
	}
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(idle)})
	})
	if h.readErr != nil || h.c.clientShown != 0 {
		t.Fatalf("after a lowering to the %d forwarded: error %v, stack shown %d, want none and 0", idle, h.readErr, h.c.clientShown)
	}
	if h.c.clientHolds() < limit {
		t.Fatalf("the client holds %d, want the limit %d used up", h.c.clientHolds(), limit)
	}
	return h, unread
}

// waitingStream is the download nothingShown leaves open and unused at the
// full limit, besides the idle one.
const waitingStream = 101

// lateStream is a download opened after nothingShown; a client's stream
// numbers only go up.
const lateStream = waitingStream + 2

// TestFlowSendWindowLoweringKeepsFrame looks at a stream that was open when
// the stack came to be shown nothing. It held one frame of window, all of it
// shown; the lowering took that from the stack, the client holds nothing of
// the stream and so owes it no credit, and nothing would look at it again.
// It is forwarded the frame with the SETTINGS frame that took it.
func TestFlowSendWindowLoweringKeepsFrame(t *testing.T) {
	h, _ := nothingShown(t)
	s := h.c.streams[waitingStream]
	if got := h.toServer.streams[waitingStream]; got != flowShownLimited || s.downForwarded != flowShownLimited {
		t.Fatalf("with nothing shown the waiting stream may send %d, %d of it forwarded; want a frame, %d, all forwarded",
			got, s.downForwarded, flowShownLimited)
	}
}

// openRequest opens a download on id.
func (h *flowHarness) openRequest(id uint32) {
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x82}, EndHeaders: true, EndStream: true})
	})
}

// TestFlowSendWindowFrameWhateverShown opens a download at a full limit with
// the stack shown nothing. The stream has a frame of window all the same, by
// credit: with none it sent nothing that would bring credit of its own, and
// with less than a Go client returns credit for it sent that once, and stayed
// there when the limit freed, whether the client or the server freed it. With
// a frame it goes on as its reader reads, a frame at a time while the limit
// is full.
func TestFlowSendWindowFrameWhateverShown(t *testing.T) {
	h, _ := nothingShown(t)
	h.openRequest(lateStream)
	sent := int64(0)
	for turn := 0; turn < 8; turn++ {
		window := h.toServer.streams[lateStream] - sent
		if window != flowShownLimited {
			t.Fatalf("turn %d: the new stream may send %d at a full limit with nothing shown, want a frame, %d", turn, window, flowShownLimited)
		}
		h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, lateStream, int(window)) })
		sent += window
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(lateStream, uint32(window)) })
	}
}

// TestFlowSendWindowServerFreesRoom is the same connection when the server
// ends the idle stream, by END_STREAM or by RST_STREAM, and the client sends
// nothing: it waits for the new stream's answer. The stream needs no frame
// from the client to have a window.
func TestFlowSendWindowServerFreesRoom(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(map[bool]string{false: "END_STREAM", true: "RST_STREAM"}[reset], func(t *testing.T) {
			h, _ := nothingShown(t)
			h.openRequest(lateStream)
			h.fromServer(func(fr *http2.Framer) {
				if reset {
					fr.WriteRSTStream(3, http2.ErrCodeCancel)
				} else {
					fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: []byte{0x88}, EndHeaders: true, EndStream: true})
				}
			})
			if got := h.toServer.streams[lateStream]; got < flowShownLimited {
				t.Fatalf("the new stream may send %d and the client owes no frame, want at least %d", got, flowShownLimited)
			}
		})
	}
}

// stuckAtLimit opens twenty downloads on a connection with the default limit,
// lets the server use all its window and runs the guard as if every stream
// had waited it out. With creditFirst the client returns 4 KiB before that.
func stuckAtLimit(t *testing.T, creditFirst bool) *flowHarness {
	t.Helper()
	h := openStreams(t, flowServerSendWindow, 4<<20, 20)
	t.Cleanup(func() { h.c.Close() })
	for id := uint32(1); id < 40; id += 2 {
		n := h.toServer.streams[id]
		h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, id, int(n)) })
		h.toServer.streams[id] -= n
	}
	if creditFirst {
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(1, 4<<10) })
	}
	h.c.mu.Lock()
	if h.c.guard != nil {
		h.c.guard.Stop()
	}
	out := h.c.unstick(time.Now().Add(time.Hour), nil)
	h.c.mu.Unlock()
	h.toServer.receive(t, out)
	return h
}

// TestFlowGuardLiftsSendWindow has a client that returns no credit until half
// of its window is read. At the limit twenty streams share 4 MiB and none
// reaches that half, so the client would never credit and the downloads would
// stop for good. The guard lifts the limit on such a connection.
func TestFlowGuardLiftsSendWindow(t *testing.T) {
	h := stuckAtLimit(t, false)
	if h.c.sendWindow != 0 {
		t.Fatalf("the guard left the limit at %d on a client that has returned no credit", h.c.sendWindow)
	}
	for id, w := range h.toServer.streams {
		if all := h.c.streams[id].downSent + w; all < 2<<20 {
			t.Fatalf("stream %d may be sent %d in all, under half of the client's window: it will never credit", id, all)
		}
	}
}

// TestFlowGuardKeepsSendWindow is the same connection once the client has
// returned 4 KiB: it credits as it reads, so it cannot be stuck for want of
// its half, and the limit stays.
func TestFlowGuardKeepsSendWindow(t *testing.T) {
	h := stuckAtLimit(t, true)
	if h.c.sendWindow != flowServerSendWindow {
		t.Fatalf("the limit is %d after the guard, want %d", h.c.sendWindow, flowServerSendWindow)
	}
	total := int64(0)
	for _, w := range h.toServer.streams {
		total += w
	}
	if total > 8<<10 {
		t.Fatalf("the guard handed out %d on a connection at its limit", total)
	}
}

// TestFlowGuardLiftIsForGood fixes how far the guard's lift goes. One
// download, far under the limit: the server uses its window, and the reader
// has taken less than a Go client returns at once, so no credit has come.
// The guard cannot tell that from a client waiting for half of its window,
// and lifts the limit with the client holding half of it. When the reader
// goes on and credit comes in small steps, the limit does not come back: one
// stream returning small credit does not show that the others do.
func TestFlowGuardLiftIsForGood(t *testing.T) {
	h := openStreams(t, flowServerSendWindow, 4<<20, 1)
	t.Cleanup(func() { h.c.Close() })
	n := h.toServer.streams[1]
	h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, 1, int(n)) })
	h.c.mu.Lock()
	if h.c.guard != nil {
		h.c.guard.Stop()
	}
	out := h.c.unstick(time.Now().Add(time.Hour), nil)
	holds, lifted := h.c.clientHolds(), h.c.sendWindow == 0
	h.c.mu.Unlock()
	h.toServer.receive(t, out)
	if !lifted || holds >= flowServerSendWindow {
		t.Fatalf("after the guard: limit lifted %v with the client holding %d of %d", lifted, holds, flowServerSendWindow)
	}
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteWindowUpdate(1, 8<<10)
		fr.WriteWindowUpdate(0, 8<<10)
	})
	if !h.c.incremental || h.c.sendWindow != 0 {
		t.Fatalf("after 8 KiB of credit: small steps seen %v, limit %d, want true and 0", h.c.incremental, h.c.sendWindow)
	}
}

// feedFrames passes frame from the client through the governor n times.
func feedFrames(tb testing.TB, h *flowHarness, frame []byte, n int) {
	buf := make([]byte, 64<<10)
	for i := 0; i < n; i++ {
		h.conn.feed(frame)
		for {
			if _, err := h.c.Read(buf); err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					tb.Fatal(err)
				}
				break
			}
		}
		h.conn.take()
	}
}

// TestFlowSendWindowSettingsCost times SETTINGS frames on connections with
// two hundred and two thousand streams past the limit. A SETTINGS frame looks
// at every stream once, so ten times the streams may cost ten times as much;
// when each look walked all the streams again it cost a hundred times.
//
// The number of frames is found first: doubled until two hundred streams
// take long enough for the clock to tell, which on Windows is milliseconds.
func TestFlowSendWindowSettingsCost(t *testing.T) {
	const enough, mostFrames = 2 * time.Millisecond, 1 << 16
	settings := frames(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	})
	connection := func(streams int) *flowHarness {
		h := openStreams(t, flowServerSendWindow, 4<<20, streams)
		t.Cleanup(func() { h.c.Close() })
		return h
	}
	cost := func(h *flowHarness, n int) time.Duration {
		best := time.Duration(math.MaxInt64)
		for try := 0; try < 5; try++ {
			start := time.Now()
			feedFrames(t, h, settings, n)
			best = min(best, time.Since(start))
		}
		return best
	}
	hFew, hMany := connection(200), connection(2000)
	n := 50
	few := cost(hFew, n)
	for few < enough && n < mostFrames {
		n = min(2*n, mostFrames)
		few = cost(hFew, n)
	}
	if few < enough {
		t.Fatalf("%d SETTINGS frames with 200 streams read as %v: the clock cannot time them", n, few)
	}
	many := cost(hMany, n)
	t.Logf("%d SETTINGS frames: %v with 200 streams, %v with 2000", n, few, many)
	if many > 40*few {
		t.Fatalf("ten times the streams made a SETTINGS frame %d times dearer", many/few)
	}
}

// refusedAtFullLimit stages a connection at a full limit where every credit
// from the client frees less than a frame: n streams the limit kept credit
// from, at a slow reader's cap and with a frame of window each, and
// completed bodies the client holds and returns 4 KiB of at a time. It
// returns the connection and where its connection window stood, to put back
// before each frame.
func refusedAtFullLimit(tb testing.TB, n int) (c *flowConn, window int64) {
	tb.Helper()
	c = newFlowConn(&scriptConn{}, flowDefault, flowDefault)
	tb.Cleanup(func() { c.Close() })
	c.sendWindow = flowServerSendWindow
	c.readFrames([]byte(h2Preface), nil)
	c.readFrames(frames(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
		for i := 0; i < n+32; i++ {
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: uint32(2*i + 1), BlockFragment: []byte{0x82}, EndHeaders: true, EndStream: true})
		}
	}), nil)
	// The streams that took the limit complete; the ones it kept credit
	// from stay open, at a slow reader's cap.
	for id, s := range c.streams {
		if s.downForwarded > 0 {
			c.drop(id)
			continue
		}
		s.down.cap = h2InitWindow
	}
	if len(c.streams) < n {
		tb.Fatalf("%d streams were kept credit from, want at least %d", len(c.streams), n)
	}
	// What the client holds of the completed bodies leaves no room.
	held := c.downOpen*int64(c.clientShown) + c.downOpenForwarded
	c.downConnHigh = 1 << 30
	c.downConnWindow = c.downConnHigh - max(flowServerSendWindow-held, 0)
	c.downConnSmall = true
	c.lastPing = time.Now()
	if c.clientHolds() < flowServerSendWindow {
		tb.Fatalf("the client holds %d, want the limit %d used up", c.clientHolds(), flowServerSendWindow)
	}
	return c, c.downConnWindow
}

// TestFlowSendWindowConnectionCreditAllocs counts what a connection
// WINDOW_UPDATE of 4 KiB allocates on that connection. Such a frame looks at
// no stream and allocates nothing. A queue of the streams the limit kept
// credit from, walked after every frame from the client, handed nothing on
// here while credit quanta held a grant of 4 KiB back, and put every stream
// back: it allocated once a frame with sixty streams. The quanta and the
// queue are gone; connection credit still looks at no stream. The count does not depend on
// the clock; BenchmarkFlowConnectionCredit has the time, which a walk that
// allocated nothing would show only there.
func TestFlowSendWindowConnectionCreditAllocs(t *testing.T) {
	credit := frames(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 4<<10) })
	c, window := refusedAtFullLimit(t, 60)
	// The state under test: room for the credit, and under a frame.
	c.downConnWindow = window + 4<<10
	if room := flowServerSendWindow - c.clientHolds(); room <= 0 || room >= h2MinMaxFrameSize {
		t.Fatalf("a credit leaves %d of room, want some and under a frame, %d", room, h2MinMaxFrameSize)
	}
	out := make([]byte, 0, 64)
	allocs := testing.AllocsPerRun(1000, func() {
		c.downConnWindow = window
		out = c.readFrames(credit, out[:0])
	})
	if allocs != 0 {
		t.Fatalf("connection credit allocated %g times a frame, want none", allocs)
	}
}

// BenchmarkFlowConnectionCredit is the cost of that frame.
func BenchmarkFlowConnectionCredit(b *testing.B) {
	credit := frames(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 4<<10) })
	for _, n := range []int{60, 240} {
		b.Run(fmt.Sprintf("streams=%d", n), func(b *testing.B) {
			c, window := refusedAtFullLimit(b, n)
			out := make([]byte, 0, 64)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.downConnWindow = window
				out = c.readFrames(credit, out[:0])
			}
		})
	}
}

// BenchmarkFlowClientFrame is the cost of one frame from the client on a
// server connection with many streams open, with and without the limit.
func BenchmarkFlowClientFrame(b *testing.B) {
	for _, kind := range []string{"settings", "windowupdate"} {
		for _, n := range []int{100, 1000} {
			for _, sendWindow := range []int64{0, flowServerSendWindow} {
				b.Run(fmt.Sprintf("%s/streams=%d/sendWindow=%d", kind, n, sendWindow), func(b *testing.B) {
					sc := &scriptConn{}
					h := &flowHarness{t: b, conn: sc, c: newFlowConn(sc, flowDefault, flowDefault)}
					h.fromClientRaw([]byte(h2Preface))
					h.c.sendWindow = sendWindow
					h.fromClient(func(fr *http2.Framer) {
						fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
					})
					for i := 0; i < n; i++ {
						h.fromClient(func(fr *http2.Framer) {
							fr.WriteHeaders(http2.HeadersFrameParam{StreamID: uint32(2*i + 1), BlockFragment: []byte{0x82}, EndHeaders: true})
						})
					}
					frame := frames(func(fr *http2.Framer) {
						if kind == "settings" {
							fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
						} else {
							fr.WriteWindowUpdate(uint32(2*n-1), 1)
						}
					})
					b.ResetTimer()
					feedFrames(b, h, frame, b.N)
				})
			}
		}
	}
}

// TestH2SendWindow checks what "maxConnectionSendWindow" means.
func TestH2SendWindow(t *testing.T) {
	for _, tc := range []struct {
		set  int32
		want int64
	}{{0, flowServerSendWindow}, {-1, 0}, {8 << 20, 8 << 20}} {
		c := &Config{H2Flow: &H2FlowConfig{Mode: 1, MaxConnectionSendWindow: tc.set}}
		if got := c.h2SendWindow(); got != tc.want {
			t.Errorf("maxConnectionSendWindow %d: limit %d, want %d", tc.set, got, tc.want)
		}
	}
	if got := (&Config{}).h2SendWindow(); got != flowServerSendWindow {
		t.Errorf("no h2Flow: limit %d, want %d", got, flowServerSendWindow)
	}
}
