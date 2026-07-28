// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// budgetFrameSize is one full DATA payload for the receive-budget death tests.
// MaxReceiveBuffer is set equal to this so a single enqueued frame saturates the
// session-wide accounting and the next DATA header must park in reserveReceive.
const budgetFrameSize = 1024

// budgetDeathBudget is how long a session may remain open after the peer closes
// while readLoop is between a DATA header and its payload with the receive
// budget full. Anything longer is an unbounded leak of the carrier, loops,
// streams and reserved buffers.
const budgetDeathBudget = time.Second

func budgetFullConfig() *Config {
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	config.MaxFrameSize = budgetFrameSize
	// validateConfig requires MaxStreamBuffer <= MaxReceiveBuffer. One frame
	// saturates both; the next DATA header parks in reserveReceive (session
	// budget) before any per-stream enqueue wait can start.
	config.MaxStreamBuffer = budgetFrameSize
	config.MaxReceiveBuffer = budgetFrameSize
	// Stall timeout must not mask the wedge: if detection only arrives after
	// this window the receive-budget path is still broken.
	config.StreamStallTimeout = 5 * time.Second
	return config
}

// fillReceiveBudget drives a server session until one peer DATA frame has fully
// claimed MaxReceiveBuffer and sits unread on the stream. Returns the session
// and peer so the caller can send one more DATA header and kill the carrier.
func fillReceiveBudget(t *testing.T, wrap func(net.Conn) io.ReadWriteCloser) (*Session, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	var carrier io.ReadWriteCloser = local
	if wrap != nil {
		carrier = wrap(local)
	}
	session, err := Server(carrier, budgetFullConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Server peers own odd stream IDs.
	writePeerFrame(t, peer, frameOpen, 1, 0)
	writePeerFrame(t, peer, frameData, 1, budgetFrameSize)

	deadline := time.Now().Add(5 * time.Second)
	for liveReceiveBytes(session) < budgetFrameSize {
		if time.Now().After(deadline) {
			t.Fatalf("receive budget never filled: used=%d want=%d", liveReceiveBytes(session), budgetFrameSize)
		}
		time.Sleep(time.Millisecond)
	}
	if stream := session.lookupStream(1); stream == nil {
		t.Fatal("peer stream was never registered")
	}
	return session, peer
}

// writeDataHeaderOnly sends a DATA frame header without its payload, matching
// the leak window: readLoop has consumed the header and must still read the
// body, but with a full receive budget the pre-fix path waits on accounting
// first and never looks at the carrier again.
func writeDataHeaderOnly(t *testing.T, peer net.Conn, streamID uint32, length int) {
	t.Helper()
	var header [frameHeaderSize]byte
	encodeFrameHeader(&header, frameData, streamID, length)
	if _, err := peer.Write(header[:]); err != nil {
		t.Fatalf("peer DATA header write: %v", err)
	}
}

// awaitBudgetWait parks until readLoop has taken the next DATA header and is
// blocked before finishing that frame. net.Pipe is unbuffered, so a successful
// header write already means the header was read; a short settle is enough for
// reserveReceive to enter its wait.
func awaitBudgetWait(t *testing.T) {
	t.Helper()
	// reserveReceive only selects on receiveChanged / s.done after unlocking;
	// a few scheduler turns are plenty on a single-core CI host.
	time.Sleep(20 * time.Millisecond)
}

// TestReadLoopObservesCarrierDeathDuringReceiveBudgetWait is the P1 regression
// for the unbounded session hold when MaxReceiveBuffer is full.
//
// Sequence:
//  1. Peer fills the session receive budget with one DATA frame nobody reads.
//  2. Peer sends the next DATA header only (no payload yet).
//  3. Peer closes the carrier.
//
// Before the fix, readLoop is inside reserveReceive waiting only on budget or
// s.done, so the FIN is invisible and the session never tears down. After the
// fix, the bounded payload is read before accounting waits, so the FIN fails
// the session and frees loops, streams and buffers.
func TestReadLoopObservesCarrierDeathDuringReceiveBudgetWait(t *testing.T) {
	baseline := runtime.NumGoroutine()
	session, peer := fillReceiveBudget(t, nil)

	writeDataHeaderOnly(t, peer, 1, budgetFrameSize)
	awaitBudgetWait(t)

	elapsed := awaitCarrierDeath(t, session, peer, budgetDeathBudget)
	if elapsed > budgetDeathBudget {
		// Do not Close: a wedged readLoop makes Close hang the whole package.
		t.Fatalf("session outlived its carrier by more than %v: readLoop is parked in reserveReceive and cannot see EOF", budgetDeathBudget)
	}
	t.Logf("session terminated %v after carrier died during receive-budget wait", elapsed)

	closeWithin(t, session, budgetDeathBudget)
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("receive budget leaked: %d bytes still reserved after teardown", used)
	}
	if streams := session.NumStreams(); streams != 0 {
		t.Fatalf("streams leaked after teardown: %d still registered", streams)
	}
	assertNoGoroutineResidue(t, baseline)
}

// TestReadLoopObservesCarrierDeathDuringReceiveBudgetWaitWithoutDeadlineSupport
// is the production carrier shape: SetReadDeadline is a no-op (cnc.Connection).
// Detection must come from reading the payload, not from a deadline.
func TestReadLoopObservesCarrierDeathDuringReceiveBudgetWaitWithoutDeadlineSupport(t *testing.T) {
	baseline := runtime.NumGoroutine()
	session, peer := fillReceiveBudget(t, func(conn net.Conn) io.ReadWriteCloser {
		return stubDeadlineCarrier{Conn: conn}
	})

	writeDataHeaderOnly(t, peer, 1, budgetFrameSize)
	awaitBudgetWait(t)

	elapsed := awaitCarrierDeath(t, session, peer, budgetDeathBudget)
	if elapsed > budgetDeathBudget {
		t.Fatalf("session outlived a deadline-ignoring carrier by more than %v during receive-budget wait", budgetDeathBudget)
	}
	closeWithin(t, session, budgetDeathBudget)
	if used := liveReceiveBytes(session); used != 0 {
		t.Fatalf("receive budget leaked: %d bytes still reserved after teardown", used)
	}
	assertNoGoroutineResidue(t, baseline)
}
