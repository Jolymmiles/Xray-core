package splithttp

import (
	"testing"

	"golang.org/x/net/http2"
)

// TestFlowClientPastShownWindow sends upload data up to the windows the
// client was shown, which the server takes, and then a byte more, which ends
// the connection as a stack shown those windows would. The server's stack is
// given larger windows than the client is shown, so without the governor's
// check a client could leave it several times as much unread.
func TestFlowClientPastShownWindow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		connCredit uint32
		streamCred uint32
	}{
		{"no credit", 0, 0},
		{"connection credit", 8 << 20, 0},
		{"stream and connection credit", 8 << 20, 4 << 20},
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
			shown := min(conn, h.toClient.streams[1])
			h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, 1, int(shown)) })
			if h.readErr != nil || h.c.isBroken() {
				t.Fatalf("data within the %d shown ended the connection: %v", shown, h.readErr)
			}
			h.fromClient(func(fr *http2.Framer) { fr.WriteData(1, false, []byte{0}) })
			if h.readErr == nil || !h.c.isBroken() {
				t.Fatalf("a byte past the %d shown was taken", shown)
			}
		})
	}
}
