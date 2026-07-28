// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// carrierDeathBudget is how long a session may stay up after its peer closes the
// carrier. readLoop parks while handing a frame to a stream whose buffer is
// full, and the whole session hangs off that wait, so the budget is what
// separates "the peer went away" from "the peer went away and took a session,
// two goroutines, a conn and every queued buffer with it for half a minute".
const carrierDeathBudget = time.Second

// stallBudget must stay comfortably above carrierDeathBudget: without a watcher
// the carrier death cannot be noticed before the stall expires, and that gap is
// exactly what these tests measure.
const stallBudget = 2 * time.Second

const stallFrameSize = 1024

func stallConfig() *Config {
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	config.MaxFrameSize = stallFrameSize
	// One frame per stream fills the stream, so the second one stalls. The
	// session-wide budget stays far ahead of it: the park under test is the
	// per-stream one, and a reservation park would be a different defect.
	config.MaxStreamBuffer = stallFrameSize
	config.MaxReceiveBuffer = 64 * stallFrameSize
	config.StreamStallTimeout = stallBudget
	return config
}

// stubDeadlineCarrier is the shape of every carrier that reaches the server:
// common/mux hands Service.NewConnection a *cnc.Connection, whose
// SetReadDeadline returns nil and does nothing (common/net/cnc/connection.go).
// A liveness check that trusted that deadline would turn into an unbounded read
// and wedge readLoop permanently -- strictly worse than the stall it replaced --
// and no net.Pipe test can catch it, because net.Pipe honours deadlines.
type stubDeadlineCarrier struct {
	net.Conn
}

func (stubDeadlineCarrier) SetReadDeadline(time.Time) error  { return nil }
func (stubDeadlineCarrier) SetWriteDeadline(time.Time) error { return nil }
func (stubDeadlineCarrier) SetDeadline(time.Time) error      { return nil }

// writePeerFrame sends one frame the way a remote peer would.
func writePeerFrame(t *testing.T, peer net.Conn, command frameCommand, streamID uint32, length int) {
	t.Helper()
	var header [frameHeaderSize]byte
	encodeFrameHeader(&header, command, streamID, length)
	if _, err := peer.Write(append(header[:], make([]byte, length)...)); err != nil {
		t.Fatalf("peer write (command %d, stream %d): %v", command, streamID, err)
	}
}

// parkReadLoop drives a fresh session until readLoop is parked handing a frame
// to a stream whose buffer is full and whose owner never reads. That is the
// state in which the session stops watching its carrier. It returns the session
// and the peer end of the carrier, so the caller can kill or silence the peer
// and time what the session does about it. wrap adapts the session's end of the
// carrier; nil uses the net.Pipe conn as-is.
func parkReadLoop(t *testing.T, config *Config, streams int, wrap func(net.Conn) io.ReadWriteCloser) (*Session, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	var carrier io.ReadWriteCloser = local
	if wrap != nil {
		carrier = wrap(local)
	}
	session, err := Server(carrier, config)
	if err != nil {
		t.Fatal(err)
	}
	for stream := range streams {
		// Peers of a server session own the odd stream IDs.
		id := uint32(2*stream + 1)
		writePeerFrame(t, peer, frameOpen, id, 0)
		writePeerFrame(t, peer, frameData, id, stallFrameSize)
	}
	writePeerFrame(t, peer, frameData, 1, stallFrameSize)

	// net.Pipe is unbuffered, so the write above returning already proves
	// readLoop took the payload -- but not yet that it gave up on space for it.
	// bufferWaiting is set under stateMu at exactly that moment, and stays set
	// across the whole wait, so it is the one signal that cannot race.
	stream := session.lookupStream(1)
	if stream == nil {
		t.Fatal("peer stream was never registered")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		stream.stateMu.Lock()
		waiting := stream.bufferWaiting
		stream.stateMu.Unlock()
		if waiting {
			return session, peer
		}
		if time.Now().After(deadline) {
			t.Fatal("readLoop never parked on the full stream")
		}
		time.Sleep(time.Millisecond)
	}
}

// awaitCarrierDeath reports how long the session took to shut itself down after
// the peer closed the carrier.
func awaitCarrierDeath(t *testing.T, session *Session, peer net.Conn, budget time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.CloseChan():
		return time.Since(start)
	case <-time.After(budget):
		return budget + 1
	}
}

// closeWithin joins the carrier loops, which is what proves none of them -- nor
// an outstanding carrier watcher -- is still parked. Close is bounded and
// abandoned on timeout rather than called bare: a loop that cannot exit would
// otherwise hang the whole test binary instead of failing this one test.
func closeWithin(t *testing.T, session *Session, budget time.Duration) {
	t.Helper()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_ = session.Close()
	}()
	select {
	case <-closed:
	case <-time.After(budget):
		t.Fatal("Close never joined the carrier loops")
	}
}

func liveReceiveBytes(session *Session) int {
	session.receiveMu.Lock()
	defer session.receiveMu.Unlock()
	return session.receiveUsed
}

func TestReadLoopObservesCarrierDeathDuringStall(t *testing.T) {
	baseline := runtime.NumGoroutine()
	session, peer := parkReadLoop(t, stallConfig(), 1, nil)

	elapsed := awaitCarrierDeath(t, session, peer, carrierDeathBudget)
	if elapsed > carrierDeathBudget {
		// Deliberately not closing the session here. The failure means readLoop
		// is stuck somewhere unexpected, and a Close that then blocks would hang
		// the whole test binary rather than just this test.
		t.Fatalf("session outlived its carrier by more than %v: readLoop is parked in the stream enqueue and cannot see EOF", carrierDeathBudget)
	}
	t.Logf("session terminated %v after the carrier died", elapsed)

	closeWithin(t, session, carrierDeathBudget)
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("receive budget leaked: %d bytes still reserved after teardown", used)
	}
	assertNoGoroutineResidue(t, baseline)
}

// TestReadLoopObservesCarrierDeathWithoutDeadlineSupport is the production
// shape: the carrier accepts SetReadDeadline and ignores it. Detection has to
// come from the read itself returning EOF, not from a deadline expiring.
func TestReadLoopObservesCarrierDeathWithoutDeadlineSupport(t *testing.T) {
	baseline := runtime.NumGoroutine()
	session, peer := parkReadLoop(t, stallConfig(), 1, func(conn net.Conn) io.ReadWriteCloser {
		return stubDeadlineCarrier{Conn: conn}
	})

	elapsed := awaitCarrierDeath(t, session, peer, carrierDeathBudget)
	if elapsed > carrierDeathBudget {
		t.Fatalf("session outlived a deadline-ignoring carrier by more than %v", carrierDeathBudget)
	}
	closeWithin(t, session, carrierDeathBudget)
	assertNoGoroutineResidue(t, baseline)
}

// TestDeadlineIgnoringCarrierDoesNotWedgeAStalledReadLoop is the regression gate
// for the wedge a deadline-bounded liveness probe would have introduced. The
// carrier is alive, silent and ignores deadlines, so any check that waits on the
// carrier for the answer never gets one: the stall would never expire, the
// stream would never abort and its buffers would never come back.
func TestDeadlineIgnoringCarrierDoesNotWedgeAStalledReadLoop(t *testing.T) {
	config := stallConfig()
	config.StreamStallTimeout = 3 * carrierWatchDelay
	session, peer := parkReadLoop(t, config, 1, func(conn net.Conn) io.ReadWriteCloser {
		return stubDeadlineCarrier{Conn: conn}
	})
	defer func() { _ = peer.Close() }()
	defer func() { _ = session.Close() }()

	// The peer stays alive and says nothing for the whole stall. The stalled
	// stream must still be aborted on schedule.
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	assertStreamAborted(t, peer, 1)
	if session.IsClosed() {
		t.Fatal("watching a live carrier killed the session")
	}
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("aborting the stalled stream left %d bytes reserved", used)
	}
}

func TestCarrierDeathDoesNotSerializeAcrossStalledStreams(t *testing.T) {
	const streams = 8
	baseline := runtime.NumGoroutine()
	session, peer := parkReadLoop(t, stallConfig(), streams, nil)

	// All of these streams are full with nobody reading them and readLoop is
	// parked on one of them. Termination must cost one carrier death, not one
	// stall budget per stream.
	elapsed := awaitCarrierDeath(t, session, peer, carrierDeathBudget)
	if elapsed > carrierDeathBudget {
		t.Fatalf("%d stalled streams serialized into more than %v of teardown", streams, carrierDeathBudget)
	}
	closeWithin(t, session, carrierDeathBudget)
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("receive budget leaked: %d bytes still reserved after teardown", used)
	}
	assertNoGoroutineResidue(t, baseline)
}

// TestStalledStreamStillAbortsOnALiveCarrier pins the other half of the
// contract: watching must not shorten the stall budget an honest slow reader
// gets, and must not cost a healthy session its carrier.
func TestStalledStreamStillAbortsOnALiveCarrier(t *testing.T) {
	config := stallConfig()
	// Long enough that the watcher genuinely runs for most of the stall.
	config.StreamStallTimeout = 3 * carrierWatchDelay
	session, peer := parkReadLoop(t, config, 1, nil)
	defer func() { _ = session.Close() }()

	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	assertStreamAborted(t, peer, 1)
	if session.IsClosed() {
		t.Fatal("watching a live carrier killed the session")
	}
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("aborting the stalled stream left %d bytes reserved", used)
	}
}

// TestCarrierDeathStaysHiddenWithoutWatching is the control. It disables the fix
// by configuration -- never by editing production code, which is indistinguish-
// able from a real defect to everyone else -- and shows the wait the watcher
// removes. If this one also finishes inside the budget, the tests above prove
// nothing.
func TestCarrierDeathStaysHiddenWithoutWatching(t *testing.T) {
	watching := carrierWatchDelay
	carrierWatchDelay = time.Hour
	t.Cleanup(func() { carrierWatchDelay = watching })

	session, peer := parkReadLoop(t, stallConfig(), 1, nil)
	t.Cleanup(func() { _ = session.Close() })

	elapsed := awaitCarrierDeath(t, session, peer, stallBudget+carrierDeathBudget)
	if elapsed > stallBudget+carrierDeathBudget {
		t.Fatal("session never terminated, even after the stall budget expired")
	}
	if elapsed < carrierDeathBudget {
		t.Fatalf("control noticed the dead carrier in %v with watching disabled: something other than the watcher is ending the stall, so the tests above measure the wrong thing", elapsed)
	}
}

// assertStreamAborted waits for the close frame the session sends when a stalled
// stream runs out of its budget.
func assertStreamAborted(t *testing.T, peer net.Conn, streamID uint32) {
	t.Helper()
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(peer, header[:]); err != nil {
		t.Fatalf("no close frame arrived for the stalled stream: %v", err)
	}
	decoded, err := decodeFrameHeader(&header)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.command != frameClose || decoded.streamID != streamID {
		t.Fatalf("expected a close frame for stream %d, got command %d for stream %d", streamID, decoded.command, decoded.streamID)
	}
}

// assertNoGoroutineResidue waits for the goroutine count to fall back to what it
// was before the session existed. Goroutines from a previous test may still be
// unwinding, so this settles rather than sampling once.
func assertNoGoroutineResidue(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine residue after teardown: %d goroutines, baseline %d", current, baseline)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
