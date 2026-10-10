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
// only the protocol's default window.
func granted(h *flowHarness) (total int64, atDefault int) {
	for _, w := range h.toServer.streams {
		total += w
		if w == h2InitWindow {
			atDefault++
		}
	}
	return total, atDefault
}

// TestFlowSendWindowBoundsManyStreams opens forty streams at once. Without a
// limit each starts with flowStartWindow, 10 MiB in all that the client must
// be ready to hold. With the limit the streams share it; those opened once it
// is used up keep the protocol's default window, which cannot be withheld, and
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
		t.Fatalf("%d of %d streams have only the default window", atDefault, n)
	}
	// The streams that got more than the default fill the limit and stop.
	above := total - int64(atDefault)*h2InitWindow
	if above > flowServerSendWindow || above < flowServerSendWindow-flowStartWindow {
		t.Fatalf("streams above the default window may send %d, the limit is %d", above, flowServerSendWindow)
	}
	for id, w := range h.toServer.streams {
		if w < h2InitWindow {
			t.Fatalf("stream %d was left with a window of %d, below the protocol default", id, w)
		}
	}
	t.Logf("%d streams: %d in all with the limit, %d without", n, total, n*flowStartWindow)
}

// TestFlowSendWindowFollowsClientWindow gives the same streams to a client
// that grants 16 MiB per stream, as a bridge with raised windows does: it has
// room for more than the limit, so its own window is the limit.
func TestFlowSendWindowFollowsClientWindow(t *testing.T) {
	const n = 40
	total, _ := granted(openStreams(t, flowServerSendWindow, 16<<20, n))
	if total != n*flowStartWindow {
		t.Fatalf("server may send %d to a client granting 16 MiB a stream, want %d", total, n*flowStartWindow)
	}
}

// TestFlowSendWindowIsReturned fills the limit, lets the client read eight
// streams, and checks that a stream held to the default window then gets more.
func TestFlowSendWindowIsReturned(t *testing.T) {
	const n = 40
	h := openStreams(t, flowServerSendWindow, 4<<20, n)
	last := uint32(2*n - 1)
	if got := h.toServer.streams[last]; got != h2InitWindow {
		t.Fatalf("the last stream opened with %d, want the default %d once the limit is used up", got, h2InitWindow)
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
	h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, last, h2InitWindow) })
	h.toServer.streams[last] -= h2InitWindow
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(last, h2InitWindow) })
	if got := h.toServer.streams[last]; got <= h2InitWindow {
		t.Fatalf("with the limit free again the last stream may send %d, want more than %d", got, h2InitWindow)
	}
}

// TestFlowSendWindowLeavesFinishedDownloadsOut fixes what the limit does not
// cover. Sixteen downloads are sent all they may and ended, and the client
// reads nothing; the next sixteen get the whole limit again. The limit is on
// the streams the server has not finished: an ended one cannot be followed,
// see clientHolds.
func TestFlowSendWindowLeavesFinishedDownloadsOut(t *testing.T) {
	h := openStreams(t, flowServerSendWindow, 4<<20, 0)
	next := uint32(1)
	round := func() (sent int64) {
		var ids []uint32
		for i := 0; i < 16; i++ {
			id := next
			next += 2
			ids = append(ids, id)
			h.fromClient(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x82}, EndHeaders: true, EndStream: true})
			})
		}
		for _, id := range ids {
			w := h.toServer.streams[id]
			h.fromServer(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x88}, EndHeaders: true})
				writeDataSplit(fr, id, int(w))
				fr.WriteData(id, true, nil)
			})
			sent += w
		}
		return sent
	}
	for n := 1; n <= 2; n++ {
		if sent := round(); sent != flowServerSendWindow {
			t.Fatalf("round %d: sixteen downloads were sent %d, want the limit %d", n, sent, flowServerSendWindow)
		}
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
		t.Errorf("no h2Flow: limit %d, want the default %d", got, flowServerSendWindow)
	}
}
