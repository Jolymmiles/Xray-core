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

// TestFlowSendWindowIsReturned fills the limit, lets the client read eight
// streams, and checks that a stream held to that then gets more.
func TestFlowSendWindowIsReturned(t *testing.T) {
	const n = 40
	h := openStreams(t, flowServerSendWindow, 4<<20, n)
	last := uint32(2*n - 1)
	if got := h.toServer.streams[last]; got != flowShownLimited {
		t.Fatalf("the last stream opened with %d, want %d once the limit is used up", got, flowShownLimited)
	}
	// The client reads all of the first eight streams' data.
	for id := uint32(1); id <= 15; id += 2 {
		w := int(h.toServer.streams[id])
		h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, id, w) })
		h.toServer.streams[id] -= int64(w)
		h.fromServer(func(fr *http2.Framer) { fr.WriteData(id, true, nil) })
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, uint32(w)) })
	}
	// The last stream sends its window and the client reads it.
	h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, last, flowShownLimited) })
	h.toServer.streams[last] -= flowShownLimited
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(last, flowShownLimited) })
	if got := h.toServer.streams[last]; got <= flowShownLimited {
		t.Fatalf("with the limit free again the last stream may send %d, want more than %d", got, flowShownLimited)
	}
}

// finishedRounds opens downloads in rounds of sixteen on h. The server sends
// each all it may and ends it, and the client reads nothing. It returns what
// each round was sent.
func finishedRounds(h *flowHarness, rounds int) (sent []int64) {
	next := uint32(1)
	for id := range h.toServer.streams {
		next = max(next, id+2)
	}
	for ; rounds > 0; rounds-- {
		var ids []uint32
		for i := 0; i < 16; i++ {
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
		t.Fatalf("the first sixteen downloads were sent %d, want the limit %d", sent[0], flowServerSendWindow)
	}
	if sent[1] != 16*flowShownLimited {
		t.Fatalf("with %d unread the next sixteen downloads were sent %d, want that window each, %d", sent[0], sent[1], 16*flowShownLimited)
	}
	// The client reads it all, 16 KiB at a time.
	for left := sent[0] + sent[1]; left > 0; left -= min(left, 16<<10) {
		h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, uint32(min(left, 16<<10))) })
	}
	if again := finishedRounds(h, 1); again[0] != flowServerSendWindow {
		t.Fatalf("once the client had read everything sixteen downloads were sent %d, want %d", again[0], flowServerSendWindow)
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
			t.Fatalf("round %d: sixteen downloads were sent %d, want the limit %d", n+1, sent, flowServerSendWindow)
		}
	}
	// Half of its window read, it returns that at once.
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 7<<20) })
	if h.c.downConnSmall {
		t.Fatal("a 7 MiB connection credit was taken for a small step")
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
func TestFlowSendWindowSettingsCost(t *testing.T) {
	settings := frames(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	})
	cost := func(streams int) time.Duration {
		h := openStreams(t, flowServerSendWindow, 4<<20, streams)
		best := time.Duration(math.MaxInt64)
		for try := 0; try < 5; try++ {
			start := time.Now()
			feedFrames(t, h, settings, 50)
			best = min(best, time.Since(start))
		}
		return best
	}
	few, many := cost(200), cost(2000)
	t.Logf("50 SETTINGS frames: %v with 200 streams, %v with 2000", few, many)
	if many > 40*few {
		t.Fatalf("ten times the streams made a SETTINGS frame %d times dearer", many/few)
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
