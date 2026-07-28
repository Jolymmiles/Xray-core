// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"bytes"
	"testing"
)

// queuedReceiveUsed reads the session-wide receive reservation.
func queuedReceiveUsed(session *Session) int {
	session.receiveMu.Lock()
	defer session.receiveMu.Unlock()
	return session.receiveUsed
}

// enqueueFilledChunk mirrors readLoop's accounting: reserve the session budget,
// acquire a receive buffer, fill it, then hand ownership to the stream. Filling
// matters -- an unread buf.Buffer has Len() 0, so an unfilled chunk would
// reserve budget the stream never accounts for.
func enqueueFilledChunk(t *testing.T, stream *Stream, size int) {
	t.Helper()
	if !stream.session.reserveReceive(size) {
		t.Fatalf("reserveReceive(%d) failed", size)
	}
	buffer := acquireReceiveBuffer(size)
	if err := buffer.readFullFrom(bytes.NewReader(make([]byte, size)), size); err != nil {
		t.Fatalf("filling receive buffer: %v", err)
	}
	if !stream.enqueue(buffer) {
		t.Fatalf("enqueue(%d) failed", size)
	}
}

// TestStreamReleaseQueuedReturnsBuffersAndBudget covers the drain helper that
// session teardown needs (D7/M3).
//
// Marking a stream closed is not enough: whatever is still queued in
// Stream.chunks holds both pooled buffers and a slice of the session-wide
// receive reservation. Leaving the reservation behind is the observable defect
// -- the buffers are pooled so GC still reclaims them, but receiveUsed is never
// decremented, and once it saturates MaxReceiveBuffer every later reserve on
// that session blocks forever.
func TestStreamReleaseQueuedReturnsBuffersAndBudget(t *testing.T) {
	const (
		payload = 2048
		chunks  = 3
	)
	session, _ := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = payload
		config.MaxStreamBuffer = payload * chunks
		config.MaxReceiveBuffer = payload * chunks
	})

	// Not registered in session.streams: releaseQueued owns only the stream's
	// own queue, so the map is deliberately out of scope here.
	stream := newStream(session, 99)
	for range chunks {
		enqueueFilledChunk(t, stream, payload)
	}

	if used := queuedReceiveUsed(session); used != payload*chunks {
		t.Fatalf("receiveUsed before release = %d, want %d", used, payload*chunks)
	}

	stream.releaseQueued()

	if used := queuedReceiveUsed(session); used != 0 {
		t.Fatalf("receiveUsed = %d after releaseQueued, want 0: budget leaked", used)
	}
	stream.stateMu.Lock()
	remaining, buffered := len(stream.chunks), stream.buffered
	stream.stateMu.Unlock()
	if remaining != 0 || buffered != 0 {
		t.Fatalf("chunks = %d, buffered = %d after releaseQueued, want 0, 0", remaining, buffered)
	}

	// The whole budget must be reusable, or the carrier wedges behind a stream
	// that is already gone.
	if !session.reserveReceive(payload * chunks) {
		t.Fatal("receive budget was not fully reusable after releaseQueued")
	}
	session.releaseReceive(payload * chunks)
}

// TestStreamReleaseQueuedIsIdempotent pins the property that makes releaseQueued
// safe to call from session teardown: fail() may reach a stream that Close or
// Abort already drained. drainLocked nils s.chunks under stateMu, so a second
// call finds nothing and must not double-release a pooled buffer (buf.Buffer has
// no refcount -- a double Release is memory corruption, D7) nor drive the
// session reservation negative.
func TestStreamReleaseQueuedIsIdempotent(t *testing.T) {
	const payload = 2048
	session, _ := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = payload
		config.MaxStreamBuffer = payload
		config.MaxReceiveBuffer = payload
	})

	stream := newStream(session, 99)
	enqueueFilledChunk(t, stream, payload)

	stream.releaseQueued()
	stream.releaseQueued()

	if used := queuedReceiveUsed(session); used != 0 {
		t.Fatalf("receiveUsed = %d after a repeated release, want 0", used)
	}
	if !session.reserveReceive(payload) {
		t.Fatal("receive budget unusable after a repeated release")
	}
	session.releaseReceive(payload)
}

// TestStreamReleaseQueuedAfterCloseKeepsBudgetBalanced pairs releaseQueued with
// the existing M3 drain in Close. Close already hands back its queue, so the
// follow-up release from session teardown must be a no-op rather than a second
// decrement of the same bytes.
func TestStreamReleaseQueuedAfterCloseKeepsBudgetBalanced(t *testing.T) {
	const payload = 2048
	session, _ := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = payload
		config.MaxStreamBuffer = payload
		config.MaxReceiveBuffer = payload
	})

	stream := newStream(session, 99)
	enqueueFilledChunk(t, stream, payload)

	if err := stream.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if used := queuedReceiveUsed(session); used != 0 {
		t.Fatalf("receiveUsed = %d after Close, want 0", used)
	}

	stream.releaseQueued()

	if used := queuedReceiveUsed(session); used != 0 {
		t.Fatalf("receiveUsed = %d after Close plus releaseQueued, want 0", used)
	}
	if !session.reserveReceive(payload) {
		t.Fatal("receive budget unusable after Close plus releaseQueued")
	}
	session.releaseReceive(payload)
}
