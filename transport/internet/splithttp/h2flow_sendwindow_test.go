package splithttp

import (
	"testing"

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

// TestFlowSendWindowIsReturned fills the limit, lets the client read one
// stream, and checks that a stream held to the default window then gets more.
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
