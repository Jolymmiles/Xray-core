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
