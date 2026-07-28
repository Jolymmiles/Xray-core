package singmux

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gatedConn is a net.Conn whose Read and Write block until the test releases
// them, and whose Close interrupts both.
//
// Close interrupting a pending Write is deliberately a property of this fake,
// not of every carrier: mplsmux.Stream.Close acquires the same writeMu that
// Stream.Write holds for its whole duration (stream.go:192, stream.go:232), so
// it serializes behind an in-flight write instead of interrupting it. Tests
// that rely on Close unblocking a write therefore prove a bound on this fake,
// and say so in their name.
type gatedConn struct {
	readGate  chan error
	writeGate chan error

	writeEnteredOnce sync.Once
	writeEntered     chan struct{}

	deadlineMu    sync.Mutex
	writeDeadline time.Time

	closeOnce  sync.Once
	closed     chan struct{}
	closeCalls atomic.Int32
}

func newGatedConn() *gatedConn {
	return &gatedConn{
		readGate:     make(chan error, 1),
		writeGate:    make(chan error, 1),
		writeEntered: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *gatedConn) Read(destination []byte) (int, error) {
	select {
	case err := <-c.readGate:
		if err == nil {
			return 0, errors.New("gated conn read released without an error")
		}
		return 0, err
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *gatedConn) Write(source []byte) (int, error) {
	c.writeEnteredOnce.Do(func() { close(c.writeEntered) })
	// Honour write deadlines the way mplsmux.Stream does, so a test can assert
	// that a replay is bounded by its deadline rather than by Close.
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	c.deadlineMu.Unlock()
	var expired <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case err := <-c.writeGate:
		if err != nil {
			return 0, err
		}
		return len(source), nil
	case <-expired:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *gatedConn) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *gatedConn) LocalAddr() net.Addr             { return nil }
func (c *gatedConn) RemoteAddr() net.Addr            { return nil }
func (c *gatedConn) SetDeadline(time.Time) error     { return nil }
func (c *gatedConn) SetReadDeadline(time.Time) error { return nil }

func (c *gatedConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

var _ net.Conn = (*gatedConn)(nil)

func unavailableOpener(context.Context) (net.Conn, error) {
	return nil, errors.New("opener must not be called")
}

// TestRetryConnReadUnblocksOnClose covers a reader parked in awaitResponse
// waiting for a replacement that will never be produced.
//
// A healthy but slow Write holds writeMu, so awaitResponse's TryLock fails and
// the reader waits on c.replaced. That writer never fails, so it never calls
// replaceLocked and never signals c.replaced. Without a close signal in that
// select, Close cannot wake the reader and only context cancellation can --
// which never comes for a long-lived inbound context. The context here is
// deliberately Background so ctx.Done() cannot mask the defect.
func TestRetryConnReadUnblocksOnClose(t *testing.T) {
	initial := newGatedConn()
	connection := newRetryConn(context.Background(), initial, unavailableOpener)

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_, _ = connection.Write([]byte("request"))
	}()
	<-initial.writeEntered

	readDone := make(chan error, 1)
	go func() {
		destination := make([]byte, 4)
		_, err := connection.Read(destination)
		readDone <- err
	}()

	// Fail the response read so awaitResponse takes the retry path, then give
	// the reader a moment to reach the select before closing.
	//
	// The sleep is what makes this a real assertion -- do not shorten it. If
	// Close lands before the reader parks, c.current() returns net.ErrClosed
	// and Read unwinds without ever reaching the select, so the test would pass
	// without exercising the defect.
	initial.readGate <- errors.New("carrier read failed")
	time.Sleep(50 * time.Millisecond)

	_ = connection.Close()

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Read remained parked in awaitResponse after Close")
	}
	<-writeDone
}

// TestRetryConnClosesConnDialedAfterClose proves a replacement that loses the
// race against Close is closed rather than dropped: without this the dialed
// stream and its carrier session would be retained with no owner.
func TestRetryConnClosesConnDialedAfterClose(t *testing.T) {
	initial := newGatedConn()
	initial.writeGate <- errors.New("carrier write failed")

	replacement := newGatedConn()
	dialEntered := make(chan struct{})
	releaseDial := make(chan struct{})
	opener := func(context.Context) (net.Conn, error) {
		close(dialEntered)
		<-releaseDial
		return replacement, nil
	}

	connection := newRetryConn(context.Background(), initial, opener)
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_, _ = connection.Write([]byte("request"))
	}()

	<-dialEntered
	_ = connection.Close()
	close(releaseDial)

	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Write remained blocked after Close")
	}
	if replacement.closeCalls.Load() == 0 {
		t.Fatal("replacement dialed after Close was dropped without being closed")
	}
}

// TestRetryConnReplayWriteIsBoundedWithoutClose is the T6 defect (S2 L3): the
// replay write is deadline-less while holding writeMu.
//
// On a real carrier nothing rescues it. mplsmux.Stream.Write blocks until the
// carrier drains, and Stream.Close cannot interrupt it because Close takes the
// same stream writeMu (stream.go:192, stream.go:232) -- so a stalled carrier
// pins the retry connection, its replay of up to maxReplayBytes (2 MiB), and
// the replay goroutine, until the whole session dies. Close is deliberately not
// called here: the replay must bound itself.
func TestRetryConnReplayWriteIsBoundedWithoutClose(t *testing.T) {
	initial := newGatedConn()
	initial.writeGate <- nil // first write succeeds, so a replay is remembered

	replacement := newGatedConn() // never released: the replay must time out
	opener := func(context.Context) (net.Conn, error) { return replacement, nil }
	connection := newRetryConn(context.Background(), initial, opener)
	connection.replayTimeout = 50 * time.Millisecond

	if _, err := connection.Write([]byte("replayable")); err != nil {
		t.Fatalf("Write error = %v, want nil", err)
	}

	readDone := make(chan error, 1)
	go func() {
		destination := make([]byte, 4)
		_, err := connection.Read(destination)
		readDone <- err
	}()

	initial.readGate <- errors.New("carrier read failed")
	<-replacement.writeEntered

	deadline := time.Now().Add(2 * time.Second)
	for {
		if connection.writeMu.TryLock() {
			connection.writeMu.Unlock()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replay pinned writeMu with no deadline; only Close or a dead session would release it")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if replacement.closeCalls.Load() == 0 {
		t.Fatal("replacement was not closed after its replay timed out")
	}

	_ = connection.Close()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Read remained blocked after Close")
	}
}

// TestRetryConnReplayGoroutineExitsWhenCloseInterruptsWrite bounds the
// asynchronous replay goroutine in awaitResponse. That goroutine selects on
// nothing: it exits only when writeFull returns, so it inherits whatever
// interrupt semantics the replacement conn offers. This asserts the bound for a
// conn whose Close interrupts a pending write; a carrier that serializes Close
// behind Write (mplsmux.Stream) leaves it parked until the session dies.
func TestRetryConnReplayGoroutineExitsWhenCloseInterruptsWrite(t *testing.T) {
	initial := newGatedConn()
	initial.writeGate <- nil // first write succeeds, so a replay is remembered

	replacement := newGatedConn()
	opener := func(context.Context) (net.Conn, error) { return replacement, nil }
	connection := newRetryConn(context.Background(), initial, opener)

	if _, err := connection.Write([]byte("replayable")); err != nil {
		t.Fatalf("Write error = %v, want nil", err)
	}

	readDone := make(chan error, 1)
	go func() {
		destination := make([]byte, 4)
		_, err := connection.Read(destination)
		readDone <- err
	}()

	// Fail the first response read so awaitResponse retries, wins TryLock and
	// hands the replay to the goroutine, which then blocks on the replacement.
	initial.readGate <- errors.New("carrier read failed")
	<-replacement.writeEntered

	_ = connection.Close()

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Read remained blocked after Close")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if connection.writeMu.TryLock() {
			connection.writeMu.Unlock()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("replay goroutine still holds writeMu after Close")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
