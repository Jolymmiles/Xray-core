package splithttp

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestFlowPingIsRandom(t *testing.T) {
	c := &flowConn{}
	seen := map[uint64]bool{}
	for range 64 {
		frame := c.appendPingFrame(nil)
		if len(frame) != 17 || frame[3] != h2Ping || frame[4] != 0 {
			t.Fatalf("not a PING frame: %x", frame)
		}
		payload := binary.BigEndian.Uint64(frame[9:])
		if seen[payload] {
			t.Fatalf("PING payload %x repeated", payload)
		}
		seen[payload] = true
	}

	c.pingSentAt = time.Now()
	ack := h2Frame{typ: h2Ping, flags: h2FlagAck}
	other := binary.BigEndian.AppendUint64(nil, c.pingData+1)
	if c.pingAck(ack, other) {
		t.Fatal("took the ACK of someone else's PING for ours")
	}
	if !c.pingAck(ack, binary.BigEndian.AppendUint64(nil, c.pingData)) {
		t.Fatal("did not recognize the ACK of our PING")
	}
}

func TestFlowPingQueueing(t *testing.T) {
	ms := time.Millisecond
	now := time.Unix(100, 0)
	for _, tc := range []struct {
		floor, last, pending time.Duration
		want                 int
	}{
		{50 * ms, 70 * ms, 0, 0},
		{50 * ms, 80 * ms, 0, 1},
		{50 * ms, 110 * ms, 0, 2},
		{ms, 10 * ms, 0, 0},
		{ms, 30 * ms, 0, 1},
		{ms, 50 * ms, 0, 2},
		{50 * ms, 60 * ms, 300 * ms, 2}, // an ACK long overdue is a queue too
		{50 * ms, 60 * ms, 20 * ms, 0},
	} {
		c := &flowConn{rttBase: tc.floor, rttLast: tc.last}
		if tc.pending > 0 {
			c.pingSentAt = now.Add(-tc.pending)
		}
		if got := c.pingQueueing(now); got != tc.want {
			t.Errorf("floor %v, last %v, pending %v: got %d, want %d", tc.floor, tc.last, tc.pending, got, tc.want)
		}
	}
	if got := (&flowConn{}).pingQueueing(now); got != 0 {
		t.Errorf("before any round trip: got %d", got)
	}
}

func TestFlowFirstPingBeforeStreams(t *testing.T) {
	c := &flowConn{pingReady: true}
	if out := c.appendPing(nil); len(out) != 17 {
		t.Fatal("no PING on a fresh connection without streams")
	}
	c.pingAck(h2Frame{typ: h2Ping, flags: h2FlagAck}, binary.BigEndian.AppendUint64(nil, c.pingData))
	if c.rttBase == 0 {
		t.Fatal("the first ACK did not set the floor")
	}
	c.lastPing = time.Time{}
	if out := c.appendPing(nil); len(out) != 0 {
		t.Fatal("idle connection keeps pinging once its floor is known")
	}
}

func TestFlowPingFloor(t *testing.T) {
	ms := time.Millisecond
	now := time.Unix(100, 0)
	for _, tc := range []struct {
		name         string
		ping, kernel time.Duration
		want         time.Duration
	}{
		{"direct, first ACK held up by slow start", 300 * ms, 150 * ms, 150 * ms},
		{"TCP proxy in front", 150 * ms, ms, 150 * ms},
		{"kernel slower than the PING", 100 * ms, 120 * ms, 100 * ms},
		{"no kernel view", 300 * ms, 0, 300 * ms},
	} {
		c := &flowConn{rttBase: tc.ping}
		if tc.kernel > 0 {
			c.tcp, c.kAt, c.kOK = fakeRawConn{}, now, true
			c.kstat = tcpStats{rtt: tc.kernel, minRTT: tc.kernel}
		}
		if got := c.pingFloor(now); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFlowQueueShrink(t *testing.T) {
	ms := time.Millisecond
	now := time.Unix(100, 0)
	c := &flowConn{rttBase: 150 * ms, rtt: 300 * ms, rttSince: now, rttSamples: 1}
	w := flowWindow{cap: 8 << 20, prev: 3 << 20}
	c.queueShrink(&w, now, h2InitWindow)
	if w.cap != 6<<20 {
		t.Fatalf("first shrink: got %d, want a quarter off", w.cap)
	}
	c.queueShrink(&w, now, h2InitWindow)
	if w.cap != 6<<20 {
		t.Fatal("shrank twice on one PING sample")
	}
	for range 10 {
		c.rttSamples++
		c.queueShrink(&w, now, h2InitWindow)
	}
	// 3 MiB per 300 ms is 1.5 MiB per 150 ms round trip of the empty path.
	if w.cap != 3<<19 {
		t.Fatalf("shrank to %d, below what the reader takes per empty round trip", w.cap)
	}
}

func TestFlowFloorConfirmed(t *testing.T) {
	ms := time.Millisecond
	now := time.Unix(100, 0)
	for _, tc := range []struct {
		name         string
		ping, kernel time.Duration
		want         bool
	}{
		{"direct", 300 * ms, 150 * ms, true},
		{"direct, no PING yet", 0, 150 * ms, true},
		{"TCP proxy in front", 150 * ms, ms, false},
		{"no kernel view", 150 * ms, 0, false},
	} {
		c := &flowConn{rttBase: tc.ping}
		if tc.kernel > 0 {
			c.tcp, c.kAt, c.kOK = fakeRawConn{}, now, true
			c.kstat = tcpStats{rtt: tc.kernel, minRTT: tc.kernel}
		}
		if got := c.floorConfirmed(now); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestFlowPingClockRecheck runs the PING check of a frame boundary on a path
// the kernel vouches for: it reads the clock once and leaves the next
// flowPingRecheck boundaries alone. When the kernel's view is lost meanwhile,
// the PING goes out at the first boundary after those.
func TestFlowPingClockRecheck(t *testing.T) {
	ms := time.Millisecond
	c := &flowConn{pingReady: true, rttBase: 50 * ms, streams: map[uint32]*flowStream{1: {}}}
	c.tcp, c.kAt, c.kOK = fakeRawConn{}, time.Now(), true
	c.kstat = tcpStats{rtt: 50 * ms, minRTT: 50 * ms}
	if out := c.appendPing(nil); len(out) != 0 || c.pingSkip != flowPingRecheck {
		t.Fatalf("modelled path: %d bytes written, %d boundaries to skip, want 0 and %d", len(out), c.pingSkip, flowPingRecheck)
	}
	c.tcp = nil
	for i := 0; i < flowPingRecheck; i++ {
		if out := c.appendPing(nil); len(out) != 0 {
			t.Fatalf("PING at boundary %d of the %d to skip", i+1, flowPingRecheck)
		}
	}
	if out := c.appendPing(nil); len(out) == 0 {
		t.Fatal("no PING once the skipped boundaries had passed")
	}
}
