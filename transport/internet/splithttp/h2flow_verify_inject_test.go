package splithttp

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestFlowInjectedWriteFailureIsTerminal makes the socket take only part of
// the credit the governor injects for a new upload stream. The client would
// then read a torn frame followed by whatever the server writes next, so the
// governor must close the connection and drop its state instead of carrying
// on.
func TestFlowInjectedWriteFailureIsTerminal(t *testing.T) {
	h := newFlowHarness(t)
	// Since the server shows Go's 1 MiB, the governor credits a new upload
	// stream at once only when the connection learned a larger window, out
	// of the 6 MiB a governed server grants.
	h.c.upLearned = flowLearned{cap: 4 << 20, at: time.Now()}
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	})
	h.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6 << 20})
	})

	h.conn.mu.Lock()
	h.conn.failNext = true
	h.conn.mu.Unlock()
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}, EndHeaders: true})
	})
	h.conn.mu.Lock()
	injected := !h.conn.failNext
	h.conn.mu.Unlock()
	if !injected {
		t.Fatal("the governor injected no credit for the new upload stream")
	}

	if !h.conn.isClosed() {
		t.Fatal("connection still open after the socket took only part of the governor's frames")
	}
	h.c.mu.Lock()
	streams, queued := len(h.c.streams), queuedBytes(h.c)
	h.c.mu.Unlock()
	if streams != 0 || queued != 0 {
		t.Fatalf("%d streams and %d queued bytes kept after the connection failed", streams, queued)
	}
	if _, err := h.fromServerRaw(frames(func(fr *http2.Framer) { fr.WriteData(1, false, make([]byte, 100)) })); err == nil {
		t.Fatal("the server could still write after a torn frame")
	}
}

// TestFlowInjectedWriteFailureTearsStream (added for bdbac60e) shows what the
// client reads after a short write of the governor's own frames. The torn
// half is already on the wire, so the client sees the connection end inside a
// frame, as with a stock stack whose socket fails mid-write; nothing the
// server writes afterwards may follow it.
func TestFlowInjectedWriteFailureTearsStream(t *testing.T) {
	h := newFlowHarness(t)
	// Since the server shows Go's 1 MiB, the governor credits a new upload
	// stream at once only when the connection learned a larger window, out
	// of the 6 MiB a governed server grants.
	h.c.upLearned = flowLearned{cap: 4 << 20, at: time.Now()}
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	})
	settings := h.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6 << 20})
	})
	h.conn.mu.Lock()
	h.conn.failNext = true
	h.conn.mu.Unlock()
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}, EndHeaders: true})
	})
	torn := h.conn.take()
	next, err := h.fromServerRaw(frames(func(fr *http2.Framer) { fr.WriteData(1, false, []byte("payload")) }))
	if err == nil || len(next) > 0 {
		t.Fatalf("server wrote %d bytes after the torn frame (err=%v)", len(next), err)
	}
	wire := append(append(append([]byte(nil), settings...), torn...), next...)
	t.Logf("client reads %x", wire)
	fr := http2.NewFramer(nil, bytes.NewReader(wire))
	fr.SetMaxReadFrameSize(1 << 24)
	for {
		f, err := fr.ReadFrame()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return
		}
		if err != nil {
			t.Fatalf("stock framer on the client side: %v", err)
		}
		if d, ok := f.(*http2.DataFrame); ok && string(d.Data()) != "payload" {
			t.Fatalf("DATA arrives as %q", d.Data())
		}
		t.Logf("frame %v", f.Header())
	}
}
