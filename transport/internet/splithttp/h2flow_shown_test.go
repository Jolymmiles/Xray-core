package splithttp

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestFlowClientPastShownWindow sends upload data up to the windows the
// client was shown, which the server takes, and then a byte more, which a
// stack shown those windows answers as the stock one does: past the stream's
// window the stream is reset with FLOW_CONTROL_ERROR, to the stack and to the
// client, and another stream goes on; past the connection's the connection
// ends. The server's stack is given larger windows than the client is shown,
// so without the governor's check a client could leave it several times as
// much unread.
func TestFlowClientPastShownWindow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		connCredit uint32
		streamCred uint32
		// wideConn shows the client more of the connection than any stream
		// holds, so that the stream's window is the one it sends past.
		wideConn bool
	}{
		{"no credit", 0, 0, false},
		{"connection credit", 8 << 20, 0, false},
		{"stream and connection credit", 8 << 20, 4 << 20, false},
		{"connection window over the stream's", 8 << 20, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFlowHarness(t)
			t.Cleanup(func() { h.c.Close() })
			h.track()
			h.openStream(4 << 20)
			h.toClient.open(1)
			h.fromServer(func(fr *http2.Framer) {
				if tc.connCredit > 0 {
					fr.WriteWindowUpdate(0, tc.connCredit)
				}
				if tc.streamCred > 0 {
					fr.WriteWindowUpdate(1, tc.streamCred)
				}
			})
			conn := int64(h2InitWindow)
			for _, f := range h.toClient.frames {
				if wu, ok := f.(*http2.WindowUpdateFrame); ok && wu.StreamID == 0 {
					conn += int64(wu.Increment)
				}
			}
			if tc.wideConn {
				h.c.mu.Lock()
				h.c.upConnForwarded += 8 << 20
				h.c.mu.Unlock()
				conn += 8 << 20
			}
			shown := min(conn, h.toClient.streams[1])
			h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, 1, int(shown)) })
			if h.readErr != nil || h.c.isBroken() {
				t.Fatalf("data within the %d shown ended the connection: %v", shown, h.readErr)
			}
			h.conn.take()
			h.c.mu.Lock()
			unread := h.c.upConnSent - h.c.upConnReturned
			h.c.mu.Unlock()
			got := h.fromClient(func(fr *http2.Framer) { fr.WriteData(1, false, []byte{0}) })
			if h.toClient.streams[1] >= conn {
				if h.readErr == nil || !h.c.isBroken() {
					t.Fatalf("a byte past the connection's %d shown was taken", shown)
				}
				return
			}
			if h.readErr != nil || h.c.isBroken() {
				t.Fatalf("a byte past stream 1's %d shown ended the connection: %v", shown, h.readErr)
			}
			if !hasReset(t, got, 1) {
				t.Fatal("the stack was not told stream 1 was reset")
			}
			// Of the frame past the window the stack takes nothing into the
			// body, and the connection counts it returned, as a stack that
			// refused it returns its connection credit.
			if d := dataFrames(got); len(d) != 0 {
				t.Fatalf("%d bytes of the frame past stream 1's window reached the stack", len(d)-4)
			}
			h.c.mu.Lock()
			after := h.c.upConnSent - h.c.upConnReturned
			h.c.mu.Unlock()
			if after != unread {
				t.Fatalf("the refused frame left %d bytes unread on the connection", after-unread)
			}
			h.sync()
			if !hasReset(t, h.conn.take(), 1) {
				t.Fatal("the client was not told stream 1 was reset")
			}
			// Another stream is still usable.
			got = h.fromClient(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: []byte{0x82}, EndHeaders: true})
				fr.WriteData(3, false, make([]byte, 100))
			})
			if h.readErr != nil || h.c.isBroken() || len(dataFrames(got)) != 4+100 {
				t.Fatalf("stream 3 after the reset: %d bytes of data reached the stack, error %v", len(dataFrames(got)), h.readErr)
			}
		})
	}
}

// TestFlowWindowHugeCredit hands a window more credit in a round than a
// reader could take, as a hostile client may: the cap grows to its limit
// and stays there, where products of such rounds wrapped to a cap at init.
func TestFlowWindowHugeCredit(t *testing.T) {
	const limit = 1 << 30
	start := time.Unix(1, 0)
	var w flowWindow
	w.cap = flowStartWindow
	now := start
	w.adjust(now, 50*time.Millisecond, h2InitWindow, limit, true, false)
	w.returned += 1 << 20
	now = now.Add(60 * time.Millisecond)
	w.adjust(now, 50*time.Millisecond, h2InitWindow, limit, true, false)
	w.returned += 1 << 34
	now = now.Add(60 * time.Millisecond)
	w.adjust(now, 50*time.Millisecond, h2InitWindow, limit, true, false)
	if w.cap != limit {
		t.Fatalf("adjust: cap %d after a round of 2^34, want the limit %d", w.cap, limit)
	}
	w.returned += 1 << 40
	now = now.Add(60 * time.Millisecond)
	w.model(now, 50*time.Millisecond, h2InitWindow, limit, 1)
	if w.cap != limit {
		t.Fatalf("model: cap %d after a round of 2^40, want the limit %d", w.cap, limit)
	}
}

// hasReset reports whether b carries an RST_STREAM with FLOW_CONTROL_ERROR
// for id.
func hasReset(t *testing.T, b []byte, id uint32) bool {
	for _, f := range rawFrames(t, b) {
		if f.typ == h2RSTStream && f.stream == id && len(f.payload) == 4 && binary.BigEndian.Uint32(f.payload) == h2ErrFlowControl {
			return true
		}
	}
	return false
}
