package mux

import (
	"sync"
	"testing"
	"time"
)

type runtimeTestWorker struct {
	closeOnce sync.Once
	closed    chan struct{}
	drained   chan struct{}
}

type runtimeTestClock struct {
	now    time.Time
	ticker *runtimeTestTicker
}

type runtimeTestTicker struct {
	ticks chan time.Time
}

func (c *runtimeTestClock) Now() time.Time { return c.now }
func (c *runtimeTestClock) NewTicker(time.Duration) runtimeTicker {
	c.ticker = &runtimeTestTicker{ticks: make(chan time.Time)}
	return c.ticker
}
func (t *runtimeTestTicker) C() <-chan time.Time { return t.ticks }
func (*runtimeTestTicker) Stop()                 {}

func newRuntimeTestWorker() *runtimeTestWorker {
	return &runtimeTestWorker{closed: make(chan struct{}), drained: make(chan struct{})}
}

func (w *runtimeTestWorker) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return nil
}

func (w *runtimeTestWorker) WaitClosed() <-chan struct{} { return w.drained }

func TestRuntimeCloseRejectsNewWorkersAndWaitsForDrain(t *testing.T) {
	runtime := NewRuntime()
	worker := newRuntimeTestWorker()
	if !runtime.registerWorker(worker) {
		t.Fatal("initial worker registration failed")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	<-worker.closed
	if runtime.registerWorker(newRuntimeTestWorker()) {
		t.Fatal("runtime accepted new worker after close began")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("runtime close returned before worker drained: %v", err)
	default:
	}
	close(worker.drained)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCloseIsConcurrentAndIdempotent(t *testing.T) {
	runtime := NewRuntime()
	const closers = 16
	var wg sync.WaitGroup
	for range closers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runtime.Close(); err != nil {
				t.Errorf("Close() error: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestRuntimeXUDPStateIsIsolatedAndUsesInjectedClock(t *testing.T) {
	start := time.Unix(100, 0)
	leftClock := &runtimeTestClock{now: start}
	rightClock := &runtimeTestClock{now: start}
	left := newRuntimeWithClock(leftClock)
	right := newRuntimeWithClock(rightClock)
	t.Cleanup(func() { _ = left.Close() })
	t.Cleanup(func() { _ = right.Close() })

	id := [8]byte{1}
	key := xudpKey{GlobalID: id}
	leftFlow := &XUDP{GlobalID: id, Status: Active}
	rightFlow := &XUDP{GlobalID: id, Status: Active}
	attachment := &Session{XUDP: leftFlow, xudpGeneration: leftFlow.Generation}
	leftFlow.Attachment = attachment
	left.xudp[key] = leftFlow
	right.xudp[key] = rightFlow
	left.detachXUDPSession(attachment)
	if got := leftFlow.Expire; !got.Equal(start.Add(time.Minute)) {
		t.Fatalf("expiry = %s; want %s", got, start.Add(time.Minute))
	}

	left.expireXUDPFlows(start.Add(2 * time.Minute))
	if _, found := left.xudp[key]; found {
		t.Fatal("expired flow remained in its runtime")
	}
	if got := right.xudp[key]; got != rightFlow {
		t.Fatal("expiration in one runtime affected another runtime")
	}
}
