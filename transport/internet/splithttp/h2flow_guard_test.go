package splithttp

import (
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestFlowGuardNotPutOffByNewStreams has a stream run out of window with a
// client that credits in large steps, and then another one every 40 ms,
// sooner than the guard's delay: the guard still fires for the first.
// Moved for each new stream, it fired only once they stopped coming.
func TestFlowGuardNotPutOffByNewStreams(t *testing.T) {
	defer func(d time.Duration) { flowGuardMin = d }(flowGuardMin)
	flowGuardMin = 100 * time.Millisecond
	c := newFlowConn(&scriptConn{}, flowDefault, flowDefault)
	t.Cleanup(func() { c.Close() })
	c.mu.Lock()
	c.clientInit, c.clientShown = 1<<20, h2InitWindow
	c.incremental = false
	c.rtt = 20 * time.Millisecond
	c.mu.Unlock()
	stuck := func(id uint32) {
		c.mu.Lock()
		defer c.mu.Unlock()
		s := &flowStream{downSent: h2InitWindow}
		c.streams[id] = s
		c.armGuard(s)
	}
	stuck(1)
	for id := uint32(3); id < 23; id += 2 {
		time.Sleep(40 * time.Millisecond)
		c.mu.Lock()
		fired := c.guardProbe
		c.mu.Unlock()
		if fired {
			return
		}
		stuck(id)
	}
	t.Fatalf("stream 1 has waited %v with no probe, the guard's delay being %v", 400*time.Millisecond, flowGuardMin)
}

// TestFlowClientSeesGovernedServer feeds a governed client the server's first
// frames: a PING ahead of any reply marks the server as one that governs its
// downloads, a PING after a reply, as a stock server's keepalive, does not.
func TestFlowClientSeesGovernedServer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		frames   func(fr *http2.Framer)
		governed bool
	}{
		{"PING with the first SETTINGS", func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
			fr.WritePing(false, [8]byte{1})
		}, true},
		{"PING after a reply", func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x88}, EndHeaders: true})
			fr.WritePing(false, [8]byte{1})
		}, false},
		{"no PING", func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFlowClientConn(&scriptConn{})
			t.Cleanup(func() { c.Close() })
			c.mode.Store(flowH2)
			c.fromServer(frames(tc.frames), nil)
			c.mu.Lock()
			got := c.peerGoverned
			c.mu.Unlock()
			if got != tc.governed {
				t.Fatalf("server taken as governed: %v, want %v", got, tc.governed)
			}
		})
	}
}
