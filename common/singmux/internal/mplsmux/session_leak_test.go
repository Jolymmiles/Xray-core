// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"io"
	"sync"
	"testing"
	"time"
)

// deadlockWatchdog bounds how long a D8 regression is allowed to hang the test
// binary. When the bug is present fail() wedges inside closeOnce.Do, so every
// later Close/fail blocks forever too -- these tests must therefore never call
// Close again after a watchdog trips, and must never register a cleanup that
// does. A hung package blocks every agent's gates, not just this test.
const deadlockWatchdog = 5 * time.Second

// stalledCarrier pins writeLoop inside its very first carrier write and stays
// there until it is closed. That is the D8 precondition: the writer cannot
// drain writeQueue, so the queue fills and submitters start to block.
type stalledCarrier struct {
	stalled   chan struct{}
	closed    chan struct{}
	stallOnce sync.Once
	closeOnce sync.Once
}

func newStalledCarrier() *stalledCarrier {
	return &stalledCarrier{stalled: make(chan struct{}), closed: make(chan struct{})}
}

func (c *stalledCarrier) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *stalledCarrier) Write([]byte) (int, error) {
	c.stallOnce.Do(func() { close(c.stalled) })
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *stalledCarrier) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// stallSubmitters builds a session whose carrier is stalled and whose write
// queue is saturated, leaving one submitter parked inside the select in
// submitWithStateResult while it holds submitMu. Closing the carrier is
// registered up front so a failing test can still unwind.
func stallSubmitters(t *testing.T) (*Session, *sync.WaitGroup) {
	t.Helper()
	carrier := newStalledCarrier()
	t.Cleanup(func() { _ = carrier.Close() })

	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Client(carrier, config)
	if err != nil {
		t.Fatal(err)
	}

	openers := new(sync.WaitGroup)
	openers.Go(func() {
		if stream, err := session.OpenStream(); err == nil {
			_ = stream
		}
	})
	select {
	case <-carrier.stalled:
	case <-time.After(deadlockWatchdog):
		t.Fatal("carrier write never stalled")
	}

	// Saturate writeQueue, then add contenders so one is parked inside the
	// select holding submitMu rather than merely waiting to acquire it.
	for range writeBacklog + 64 {
		openers.Go(func() {
			if stream, err := session.OpenStream(); err == nil {
				_ = stream
			}
		})
	}
	deadline := time.Now().Add(deadlockWatchdog)
	for len(session.writeQueue) < cap(session.writeQueue) {
		if time.Now().After(deadline) {
			t.Fatalf("write queue never filled: len = %d, cap = %d", len(session.writeQueue), cap(session.writeQueue))
		}
		time.Sleep(time.Millisecond)
	}
	return session, openers
}

// completesWithin reports whether work finished before the watchdog. The
// goroutine is deliberately abandoned on timeout: with D8 present it can never
// return, and waiting for it would hang the binary.
func completesWithin(work func()) bool {
	finished := make(chan struct{})
	go func() {
		work()
		close(finished)
	}()
	select {
	case <-finished:
		return true
	case <-time.After(deadlockWatchdog):
		return false
	}
}

// A dying session must hand back the receive budget its live streams still
// hold. sessionStopped only flags a stream as dead: whatever sits in
// Stream.chunks keeps both the pooled buffers and its slice of the session-wide
// reservation. Nothing will ever drain those queues once the session is gone,
// so the reservation is the observable leak (D7/M3).
func TestSessionFailReleasesLiveStreamReceiveBudget(t *testing.T) {
	const (
		payload = 2048
		chunks  = 3
	)
	session, _ := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = payload
		config.MaxStreamBuffer = payload * chunks
		config.MaxReceiveBuffer = payload * chunks * 2
	})

	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	for range chunks {
		enqueueFilledChunk(t, stream, payload)
	}
	if used := queuedReceiveUsed(session); used != payload*chunks {
		t.Fatalf("receiveUsed before failure = %d, want %d", used, payload*chunks)
	}

	session.fail(io.ErrUnexpectedEOF)

	if used := queuedReceiveUsed(session); used != 0 {
		t.Fatalf("receiveUsed after fail = %d, want 0: a live stream's queued budget leaked", used)
	}
}

// Streams handed to accepts but never taken by AcceptStream are still live
// owners of queued buffers, so teardown has to reclaim them too.
func TestSessionFailReleasesUnacceptedStreamReceiveBudget(t *testing.T) {
	const payload = 2048
	session, _ := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = payload
		config.MaxStreamBuffer = payload * 2
		config.MaxReceiveBuffer = payload * 4
	})

	// Mirror readLoop's inbound-open path: registered in session.streams and
	// parked in accepts, with nobody calling AcceptStream.
	session.acceptRemoteStream(2)
	stream := session.lookupStream(2)
	if stream == nil {
		t.Fatal("inbound stream was not registered")
	}
	enqueueFilledChunk(t, stream, payload)
	if used := queuedReceiveUsed(session); used != payload {
		t.Fatalf("receiveUsed before failure = %d, want %d", used, payload)
	}

	session.fail(io.ErrUnexpectedEOF)

	if used := queuedReceiveUsed(session); used != 0 {
		t.Fatalf("receiveUsed after fail = %d, want 0: an unaccepted stream's queued budget leaked", used)
	}
}

// Teardown must stay exactly-once with the stream's own close path (D7/M3):
// draining twice would double-release pooled buffers and corrupt the pool.
func TestSessionFailAfterStreamCloseKeepsBudgetBalanced(t *testing.T) {
	const payload = 2048
	session, _ := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = payload
		config.MaxStreamBuffer = payload * 2
		config.MaxReceiveBuffer = payload * 4
	})

	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	enqueueFilledChunk(t, stream, payload)
	_ = stream.Close()
	if used := queuedReceiveUsed(session); used != 0 {
		t.Fatalf("receiveUsed after Close = %d, want 0", used)
	}

	session.fail(io.ErrUnexpectedEOF)

	if used := queuedReceiveUsed(session); used != 0 {
		t.Fatalf("receiveUsed after Close then fail = %d, want 0: teardown released twice", used)
	}
}

// D8: submitWithStateResult parks in its select while holding submitMu when the
// write queue is full and the carrier is stalled. submitResult passes no change
// channel and OpenStream passes a zero deadline, so the send is the only live
// case. fail() then needs submitMu before it can close(s.done), so it blocks
// forever: done never closes, the carrier is never closed, neither loop exits,
// and Close parks on loops.Wait. The whole session leaks for the process
// lifetime.
func TestSessionCloseCompletesWhenSubmitParksOnFullWriteQueue(t *testing.T) {
	session, openers := stallSubmitters(t)

	if !completesWithin(func() { _ = session.Close() }) {
		t.Fatal("Session.Close deadlocked: fail() waited on submitMu held by a submitter parked on a full writeQueue (D8)")
	}
	if !completesWithin(openers.Wait) {
		t.Fatal("submitters remained parked after Close: teardown did not wake them")
	}
}

// The same lock inversion reached through readLoop's path rather than Close: a
// dead carrier calls fail() directly, which must not need a lock that a parked
// submitter is holding.
func TestSessionFailCompletesWhenSubmitParksOnFullWriteQueue(t *testing.T) {
	session, openers := stallSubmitters(t)

	if !completesWithin(func() { session.fail(io.ErrUnexpectedEOF) }) {
		t.Fatal("fail() blocked on submitMu held by a parked submitter (D8)")
	}
	if !session.IsClosed() {
		t.Fatal("fail() returned without closing the session")
	}
	if !completesWithin(openers.Wait) {
		t.Fatal("parked submitters never woke after fail()")
	}
}
