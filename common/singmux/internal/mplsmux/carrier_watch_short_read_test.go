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

// TestCarrierWatchSurvivesFullHeaderThenFIN pins the bounded case after a
// complete header. The watcher must publish that header immediately so a valid
// zero-payload frame does not depend on future traffic. If FIN follows it while
// readLoop is still stalled, StreamStallTimeout is the finite upper bound:
// there is no carrier operation that can distinguish a silent live peer from a
// FIN that has not yet been read.
func TestCarrierWatchSurvivesFullHeaderThenFIN(t *testing.T) {
	baseline := runtime.NumGoroutine()
	config := stallConfig()
	config.StreamStallTimeout = 3 * carrierWatchDelay
	session, peer := parkReadLoop(t, config, 1, func(conn net.Conn) io.ReadWriteCloser {
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
		t.Fatalf("session still alive more than %v after full header then FIN: bounded stall did not expose carrier death", carrierDeathBudget)
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

// TestCarrierWatchProcessesCompleteHeaderWithoutFollowingByte covers the
// survive-and-resume path for a valid zero-payload control frame. A complete
// OPEN is ready to process by itself; waiting for a byte from the following
// frame makes the accepted stream depend on unrelated future traffic.
func TestCarrierWatchProcessesCompleteHeaderWithoutFollowingByte(t *testing.T) {
	baseline := runtime.NumGoroutine()
	session, peer := parkReadLoop(t, stallConfig(), 1, func(conn net.Conn) io.ReadWriteCloser {
		return stubDeadlineCarrier{Conn: conn}
	})
	defer func() { _ = peer.Close() }()
	awaitWatchReady(t)

	const resumeStreamID = uint32(3)
	var openHeader [frameHeaderSize]byte
	encodeFrameHeader(&openHeader, frameOpen, resumeStreamID, 0)
	if _, err := peer.Write(openHeader[:]); err != nil {
		t.Fatalf("peer write of complete OPEN: %v", err)
	}

	// Free stream buffer space so the stalled enqueue finishes and readLoop
	// joins the watch and processes the already-complete OPEN.
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
			t.Fatalf("accepted stream id = %d, want %d", stream.ID(), resumeStreamID)
		}
	case err := <-acceptErr:
		t.Fatalf("AcceptStream after complete watched OPEN: %v", err)
	case <-time.After(carrierDeathBudget):
		t.Fatal("complete watched OPEN was not processed without a following byte")
	case <-session.CloseChan():
		t.Fatal("session closed while processing a complete watched OPEN")
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
