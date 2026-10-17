package splithttp

import (
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// queuedPath makes c take the kernel's word for an empty path of minRTT and
// a round trip of rtt now, until the test changes it.
func queuedPath(c *flowConn, minRTT, rtt time.Duration) {
	c.tcp, c.kAt, c.kOK = fakeRawConn{}, time.Now().Add(time.Hour), true
	c.kstat = tcpStats{rtt: rtt, minRTT: minRTT}
	c.rttBase = minRTT
	if c.path == nil {
		c.path, c.pathSet = &flowPath{}, true
	}
}

// queuedDownload is a server with one download whose reader takes all it is
// sent, on a path whose round trip stands at 500 ms over an empty 50 ms: a
// queue the server must cut against. The cap is 1 MiB.
func queuedDownload(t *testing.T) (h *flowHarness, s *flowStream) {
	t.Helper()
	const id = 1
	h = newFlowHarness(t)
	t.Cleanup(func() { h.c.Close() })
	h.track()
	h.openStream(4 << 20)
	h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, id, 200<<10) })
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	queuedPath(h.c, 50*time.Millisecond, 500*time.Millisecond)
	s = h.c.streams[id]
	s.down.cap = 1 << 20
	s.down.mark, s.down.markBase = time.Now(), s.down.returned
	return h, s
}

// credit returns 4 KiB of the download's credit and gives the cap after it.
func credit(h *flowHarness, s *flowStream) int32 {
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(1, 4<<10) })
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	return s.down.cap
}

// probeRan moves the open probe and the stream's last cut flowProbeRounds
// round trips and more into the past, and sets the round trip the kernel
// reports then.
func probeRan(t *testing.T, h *flowHarness, s *flowStream, rtt time.Duration) {
	t.Helper()
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if h.c.path.probeAt.IsZero() {
		t.Fatal("a standing queue opened no probe")
	}
	back := (flowProbeRounds + 1) * h.c.path.probeRTT
	h.c.path.probeAt = h.c.path.probeAt.Add(-back)
	s.down.qAt = s.down.qAt.Add(-back)
	h.c.kstat.rtt = rtt
}

// TestFlowForeignQueueStopsCuts is a queue the server's cut does not
// shorten: the round trip stands where it was. Other traffic keeps it full,
// and cutting further would hand that traffic the path down to init per
// round trip. After the probe the queue counts as foreign: the cap is cut no
// more, and it still is not some round trips later.
func TestFlowForeignQueueStopsCuts(t *testing.T) {
	h, s := queuedDownload(t)
	first := credit(h, s)
	if first >= 1<<20 {
		t.Fatalf("against a standing queue the cap stayed at %d, want the probe's cut", first)
	}
	probeRan(t, h, s, 500*time.Millisecond)
	cut := credit(h, s)
	if cut < first {
		t.Fatalf("the cap was cut again to %d by a queue the last cut did not shorten", cut)
	}
	h.c.mu.Lock()
	foreign, open := h.c.path.foreignUntil.After(time.Now()), !h.c.path.probeAt.IsZero()
	s.down.qAt = s.down.qAt.Add(-time.Second)
	h.c.mu.Unlock()
	if !foreign || open {
		t.Fatalf("after the probe: foreign %v, a probe still open %v; want the queue foreign and the probe settled", foreign, open)
	}
	if got := credit(h, s); got < cut {
		t.Fatalf("the cap was cut to %d while the queue counts as foreign", got)
	}
}

// TestFlowOwnQueueKeepsCuts is a queue the cut did shorten: the round trip
// came down from 500 to 400 ms, a fifth of the queue. It is the server's
// own, and the next round trip is cut as before.
func TestFlowOwnQueueKeepsCuts(t *testing.T) {
	h, s := queuedDownload(t)
	first := credit(h, s)
	probeRan(t, h, s, 400*time.Millisecond)
	if got := credit(h, s); got >= first {
		t.Fatalf("the cap stayed at %d after a cut that shortened the queue, want it cut again", got)
	}
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if h.c.path.foreignUntil.After(time.Now()) {
		t.Fatal("a queue the cut shortened counts as foreign")
	}
}

// TestFlowSmallQueueOpensNoProbe is a queue at twice the setpoint's level:
// pi keeps such a queue, and no probe cuts against it. Just above, one does.
func TestFlowSmallQueueOpensNoProbe(t *testing.T) {
	c := &flowConn{streams: map[uint32]*flowStream{}}
	queuedPath(c, 50*time.Millisecond, 50*time.Millisecond+2*queueSetpoint(tcpStats{minRTT: 50 * time.Millisecond}))
	c.probeQueue(time.Now())
	if !c.path.probeAt.IsZero() {
		t.Fatal("a queue of twice the setpoint opened a probe")
	}
	c.kstat.rtt += time.Millisecond
	c.probeQueue(time.Now())
	if c.path.probeAt.IsZero() {
		t.Fatal("a queue over twice the setpoint opened no probe")
	}
}

// TestFlowProbeCutsEveryDownload is a probe on a connection with three open
// downloads and one the server has finished. All three open ones are cut at
// once to a quarter under what they have in flight, never under init: a cut
// of one stream in eight, or of a cap a stream does not fill, would move the
// queue too little to tell whose it is.
func TestFlowProbeCutsEveryDownload(t *testing.T) {
	c := &flowConn{streams: map[uint32]*flowStream{}, down: flowDefault}
	queuedPath(c, 50*time.Millisecond, 500*time.Millisecond)
	for id, st := range map[uint32][2]int32{1: {1 << 20, 1 << 20}, 3: {1 << 20, 400 << 10}, 5: {h2InitWindow, h2InitWindow}} {
		c.streams[id] = &flowStream{down: flowWindow{cap: st[0], returned: 1 << 30}, downSent: 1<<30 + int64(st[1])}
	}
	c.streams[7] = &flowStream{down: flowWindow{cap: 1 << 20}, serverDone: true}
	c.probeQueue(time.Now())
	for id, want := range map[uint32]int32{1: 768 << 10, 3: 300 << 10, 5: h2InitWindow, 7: 1 << 20} {
		if got := c.streams[id].down.cap; got != want {
			t.Errorf("stream %d: cap %d after the probe, want %d", id, got, want)
		}
	}
}

// TestFlowProbeSpansConnections is a probe one connection from a client
// opens: another from the same client cuts its downloads for it when it next
// hears from the client, and only once, for its queue is mostly the first
// one's data and the other way round.
func TestFlowProbeSpansConnections(t *testing.T) {
	path := &flowPath{}
	conns := [2]*flowConn{}
	for i := range conns {
		c := &flowConn{streams: map[uint32]*flowStream{}, down: flowDefault, path: path, pathSet: true}
		queuedPath(c, 50*time.Millisecond, 500*time.Millisecond)
		c.streams[1] = &flowStream{down: flowWindow{cap: 1 << 20}, downSent: 1 << 20}
		conns[i] = c
	}
	now := time.Now()
	conns[0].probeQueue(now)
	conns[1].kstat.rtt = 60 * time.Millisecond
	conns[1].probeQueue(now.Add(time.Millisecond))
	if got := conns[1].streams[1].down.cap; got != 768<<10 {
		t.Fatalf("the other connection's download has cap %d after the probe, want 768 KiB", got)
	}
	conns[1].probeQueue(now.Add(2 * time.Millisecond))
	if got := conns[1].streams[1].down.cap; got != 768<<10 {
		t.Fatalf("the other connection cut again to %d for the same probe", got)
	}
}
