// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// awaitWatchReady waits past the unwatched stall prefix so startCarrierWatch
// has run. parkReadLoop returns at the first bufferWaiting, still inside
// carrierWatchDelay; writing before the watch starts would not hit the defect.
// Timing is used instead of reading session.watch to keep the test race-clean.
func awaitWatchReady(t *testing.T) {
	t.Helper()
	time.Sleep(carrierWatchDelay + 50*time.Millisecond)
}

// writeThenClose delivers bytes on an unbuffered net.Pipe and only then FINs.
// Write returns after the watcher has consumed the data with err=nil, so a
// one-shot Read watch has already exited before Close runs — the regression
// the production watcher must not exhibit.
func writeThenClose(t *testing.T, peer net.Conn, payload []byte) {
	t.Helper()
	if _, err := peer.Write(payload); err != nil {
		t.Fatalf("peer write before FIN: %v", err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestCarrierWatchSurvivesOneByteThenFIN is the P1 short-read case: one successful
// Read of a single header byte used to end the watch, after which the following
// FIN was invisible until StreamStallTimeout expired.
func TestCarrierWatchSurvivesOneByteThenFIN(t *testing.T) {
	baseline := runtime.NumGoroutine()
	session, peer := parkReadLoop(t, stallConfig(), 1, func(conn net.Conn) io.ReadWriteCloser {
		return stubDeadlineCarrier{Conn: conn}
	})
	awaitWatchReady(t)

	start := time.Now()
	writeThenClose(t, peer, []byte{byte(frameKeepalive)})
	select {
	case <-session.CloseChan():
	case <-time.After(carrierDeathBudget):
		t.Fatalf("session still alive more than %v after 1-byte read then FIN: watcher exited on err=nil", carrierDeathBudget)
	}
	elapsed := time.Since(start)
	if elapsed > carrierDeathBudget {
		t.Fatalf("session outlived carrier by %v after short read+FIN", elapsed)
	}
	t.Logf("session terminated %v after 1-byte-then-FIN", elapsed)

	closeWithin(t, session, carrierDeathBudget)
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("receive budget leaked: %d bytes still reserved after teardown", used)
	}
	assertNoGoroutineResidue(t, baseline)
}

// TestCarrierWatchSurvivesFullHeaderThenFIN is the same defect with a complete
// next-frame header: a successful full-header Read also used to retire the
// watch before the FIN arrived.
func TestCarrierWatchSurvivesFullHeaderThenFIN(t *testing.T) {
	baseline := runtime.NumGoroutine()
	session, peer := parkReadLoop(t, stallConfig(), 1, func(conn net.Conn) io.ReadWriteCloser {
		return stubDeadlineCarrier{Conn: conn}
	})
	awaitWatchReady(t)

	var header [frameHeaderSize]byte
	// Keepalive is a valid inbound frame (stream ID 0) so a premature process
	// path would not itself fail the session — only the following FIN should.
	encodeFrameHeader(&header, frameKeepalive, 0, 0)

	start := time.Now()
	writeThenClose(t, peer, header[:])
	select {
	case <-session.CloseChan():
	case <-time.After(carrierDeathBudget):
		t.Fatalf("session still alive more than %v after full header then FIN: watcher exited on err=nil", carrierDeathBudget)
	}
	elapsed := time.Since(start)
	if elapsed > carrierDeathBudget {
		t.Fatalf("session outlived carrier by %v after full-header+FIN", elapsed)
	}
	t.Logf("session terminated %v after full-header-then-FIN", elapsed)

	closeWithin(t, session, carrierDeathBudget)
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("receive budget leaked: %d bytes still reserved after teardown", used)
	}
	assertNoGoroutineResidue(t, baseline)
}

// TestCarrierWatchProbeByteReplayedWithoutDesync covers the survive-and-resume
// path: after ReadFull completes a header with err=nil the watcher probes one
// more byte. That byte is the first of the next frame and must be replayed via
// watchPushback when readLoop joins — dropping it silently desyncs the protocol.
func TestCarrierWatchProbeByteReplayedWithoutDesync(t *testing.T) {
	baseline := runtime.NumGoroutine()
	session, peer := parkReadLoop(t, stallConfig(), 1, func(conn net.Conn) io.ReadWriteCloser {
		return stubDeadlineCarrier{Conn: conn}
	})
	defer func() { _ = peer.Close() }()
	awaitWatchReady(t)

	// Keepalive completes the watcher's header read with err=nil; the first byte
	// of the following OPEN is the death-probe success that sets watchPushback.
	var keepalive [frameHeaderSize]byte
	encodeFrameHeader(&keepalive, frameKeepalive, 0, 0)
	const resumeStreamID = uint32(3)
	var openHeader [frameHeaderSize]byte
	encodeFrameHeader(&openHeader, frameOpen, resumeStreamID, 0)

	probeWrite := append(append([]byte{}, keepalive[:]...), openHeader[0])
	if _, err := peer.Write(probeWrite); err != nil {
		t.Fatalf("peer write of keepalive+probe: %v", err)
	}

	// Remainder of OPEN blocks on the unbuffered pipe until readLoop resumes
	// and consumes the pushback via carrierReader.
	remainderDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(openHeader[1:])
		remainderDone <- err
	}()

	// Free stream buffer space so the stalled enqueue finishes and readLoop
	// joins the watch (processing keepalive, then the OPEN starting at the probe).
	stalled, err := session.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream stalled peer stream: %v", err)
	}
	if stalled.ID() != 1 {
		t.Fatalf("expected peer stream 1, got %d", stalled.ID())
	}
	if _, err := io.ReadFull(stalled, make([]byte, 2*stallFrameSize)); err != nil {
		t.Fatalf("drain stalled stream: %v", err)
	}

	select {
	case err := <-remainderDone:
		if err != nil {
			t.Fatalf("peer write of OPEN remainder: %v", err)
		}
	case <-time.After(carrierDeathBudget):
		t.Fatal("OPEN remainder never drained: readLoop did not resume after join")
	case <-session.CloseChan():
		t.Fatal("session failed while resuming after probe — protocol desync")
	}

	// If the probe byte was lost, the OPEN header is misaligned and stream 3
	// never appears (session fails or hangs on an invalid command).
	accepted := make(chan *Stream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		stream, err := session.AcceptStream()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- stream
	}()
	select {
	case stream := <-accepted:
		if stream.ID() != resumeStreamID {
			t.Fatalf("accepted stream id = %d, want %d (probe byte not replayed cleanly)", stream.ID(), resumeStreamID)
		}
	case err := <-acceptErr:
		t.Fatalf("AcceptStream after probe resume: %v", err)
	case <-time.After(carrierDeathBudget):
		t.Fatal("stream opened after probe never accepted — pushback dropped or desynced")
	case <-session.CloseChan():
		t.Fatal("session closed after probe resume — protocol desync on pushback replay")
	}

	if session.IsClosed() {
		t.Fatal("session closed after successful resume")
	}
	closeWithin(t, session, carrierDeathBudget)
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("receive budget leaked: %d bytes still reserved after teardown", used)
	}
	assertNoGoroutineResidue(t, baseline)
}
