package splithttp

import (
	"testing"
	"time"
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
