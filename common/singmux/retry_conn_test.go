package singmux

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type staleSuccessfulWriteConn struct {
	writeStarted chan struct{}
	readFailed   chan struct{}
}

func (c *staleSuccessfulWriteConn) Read([]byte) (int, error) {
	<-c.writeStarted
	close(c.readFailed)
	return 0, io.EOF
}

func (c *staleSuccessfulWriteConn) Write(payload []byte) (int, error) {
	close(c.writeStarted)
	<-c.readFailed
	runtime.Gosched()
	return len(payload), nil
}

func (*staleSuccessfulWriteConn) Close() error                     { return nil }
func (*staleSuccessfulWriteConn) LocalAddr() net.Addr              { return nil }
func (*staleSuccessfulWriteConn) RemoteAddr() net.Addr             { return nil }
func (*staleSuccessfulWriteConn) SetDeadline(time.Time) error      { return nil }
func (*staleSuccessfulWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*staleSuccessfulWriteConn) SetWriteDeadline(time.Time) error { return nil }

type retryReplacementConn struct {
	readMu      sync.Mutex
	reads       *bytes.Reader
	writeMu     sync.Mutex
	written     bytes.Buffer
	replayOnce  sync.Once
	replayReady chan struct{}
}

func (c *retryReplacementConn) Read(payload []byte) (int, error) {
	<-c.replayReady
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.reads.Read(payload)
}

func (c *retryReplacementConn) Write(payload []byte) (int, error) {
	c.writeMu.Lock()
	written, err := c.written.Write(payload)
	c.writeMu.Unlock()
	c.replayOnce.Do(func() { close(c.replayReady) })
	return written, err
}

func (*retryReplacementConn) Close() error                     { return nil }
func (*retryReplacementConn) LocalAddr() net.Addr              { return nil }
func (*retryReplacementConn) RemoteAddr() net.Addr             { return nil }
func (*retryReplacementConn) SetDeadline(time.Time) error      { return nil }
func (*retryReplacementConn) SetReadDeadline(time.Time) error  { return nil }
func (*retryReplacementConn) SetWriteDeadline(time.Time) error { return nil }

func (c *retryReplacementConn) writtenBytes() []byte {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return bytes.Clone(c.written.Bytes())
}

type halfClosedReadFailConn struct{ closedWrite atomic.Bool }

func (*halfClosedReadFailConn) Read([]byte) (int, error)          { return 0, io.EOF }
func (*halfClosedReadFailConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (c *halfClosedReadFailConn) CloseWrite() error               { c.closedWrite.Store(true); return nil }
func (*halfClosedReadFailConn) Close() error                      { return nil }
func (*halfClosedReadFailConn) LocalAddr() net.Addr               { return nil }
func (*halfClosedReadFailConn) RemoteAddr() net.Addr              { return nil }
func (*halfClosedReadFailConn) SetDeadline(time.Time) error       { return nil }
func (*halfClosedReadFailConn) SetReadDeadline(time.Time) error   { return nil }
func (*halfClosedReadFailConn) SetWriteDeadline(time.Time) error  { return nil }

func TestRetryConnDoesNotReplayAfterCloseWrite(t *testing.T) {
	initial := &halfClosedReadFailConn{}
	var opens atomic.Int32
	connection := newRetryConn(context.Background(), initial, func(context.Context) (net.Conn, error) { opens.Add(1); return nil, io.ErrClosedPipe })
	defer connection.Close()
	if _, err := connection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err := connection.Read(response[:]); err != io.EOF {
		t.Fatalf("read error = %v, want EOF", err)
	}
	if !initial.closedWrite.Load() {
		t.Fatal("CloseWrite was not delegated")
	}
	if got := opens.Load(); got != 0 {
		t.Fatalf("replacement opens = %d, want 0", got)
	}
}

func TestRetryConnReplacesStaleStreamAfterConcurrentSuccessfulWrite(t *testing.T) {
	previousMaxProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousMaxProcs)
	initial := &staleSuccessfulWriteConn{
		writeStarted: make(chan struct{}),
		readFailed:   make(chan struct{}),
	}
	replacement := &retryReplacementConn{
		reads:       bytes.NewReader([]byte{streamStatusSuccess, 'r'}),
		replayReady: make(chan struct{}),
	}
	var opens atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection := newRetryConn(ctx, initial, func(context.Context) (net.Conn, error) {
		opens.Add(1)
		return replacement, nil
	})
	defer connection.Close()

	payload := []byte("replay-after-successful-stale-write")
	writeResult := make(chan error, 1)
	go func() {
		_, err := connection.Write(payload)
		writeResult <- err
	}()
	select {
	case <-initial.writeStarted:
	case <-ctx.Done():
		t.Fatal("stale write did not start")
	}

	type readResult struct {
		byteValue byte
		err       error
	}
	readDone := make(chan readResult, 1)
	go func() {
		var response [1]byte
		_, err := connection.Read(response[:])
		readDone <- readResult{byteValue: response[0], err: err}
	}()
	select {
	case <-initial.readFailed:
	case <-ctx.Done():
		t.Fatal("stale read did not fail while the writer held the stream")
	}

	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatalf("stale write returned an error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("stale write did not finish")
	}

	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("read after stale stream replacement: %v", result.err)
		}
		if result.byteValue != 'r' {
			t.Fatalf("response = %q, want r", result.byteValue)
		}
	case <-ctx.Done():
		t.Fatal("read did not replace the stale stream after the writer released it")
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("replacement opens = %d, want 1", got)
	}
	if got := replacement.writtenBytes(); !bytes.Equal(got, payload) {
		t.Fatalf("replacement replay = %q, want %q", got, payload)
	}
}
