package singbridge

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
)

type panickingIOReader struct{}

func (panickingIOReader) Read([]byte) (int, error) { panic("read side exploded") }

// TestPipeConnWrapperRecoversPanic is the TCP counterpart of
// TestPacketConnWrapperRecoversPanic. bufio.CopyConn runs Read and Write on
// task.Group goroutines exactly as CopyPacketConn does, so a panic escaping
// either one ends the process instead of the connection.
func TestPipeConnWrapperRecoversPanic(t *testing.T) {
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	defer timer.SetTimeout(0)

	w := &PipeConnWrapper{
		R: panickingIOReader{},
		W: &panickingWriter{},
		T: timer,
	}

	n, err := w.Read(make([]byte, 32))
	if err == nil {
		t.Fatal("Read returned no error for a panicking reader")
	}
	if n != 0 {
		t.Fatalf("Read reported %d bytes after a panic; the caller would read uninitialised memory", n)
	}
	if !strings.Contains(err.Error(), "panic in singbridge.PipeConnWrapper.Read") {
		t.Fatalf("Read error does not name the panic: %v", err)
	}

	n, err = w.Write([]byte("payload"))
	if err == nil {
		t.Fatal("Write returned no error for a panicking writer")
	}
	if n != 0 {
		t.Fatalf("Write reported %d bytes written after a panic", n)
	}
	if !strings.Contains(err.Error(), "panic in singbridge.PipeConnWrapper.Write") {
		t.Fatalf("Write error does not name the panic: %v", err)
	}
}

// A guard is only worth having if it stays out of the way otherwise.
func TestPipeConnWrapperNormalPath(t *testing.T) {
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	defer timer.SetTimeout(0)

	sink := &collectWriter{}
	w := &PipeConnWrapper{R: strings.NewReader("hello"), W: sink, T: timer}

	b := make([]byte, 8)
	n, err := w.Read(b)
	if err != nil || n != 5 || string(b[:n]) != "hello" {
		t.Fatalf("Read = %d, %q, %v; want 5, \"hello\", nil", n, b[:n], err)
	}
	n, err = w.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Fatalf("Write = %d, %v; want 5, nil", n, err)
	}
	if got := sink.String(); got != "world" {
		t.Fatalf("writer received %q; want %q", got, "world")
	}
}

type collectWriter struct{ b []byte }

func (c *collectWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, bb := range mb {
		c.b = append(c.b, bb.Bytes()...)
	}
	return nil
}

func (c *collectWriter) String() string { return string(c.b) }

// TestPipeConnWrapperNilTimerBecomesError is the TCP counterpart of
// TestPacketConnWrapperNilTimerBecomesError: the guard owns the method from
// its first operation, and a nil timer fails as an error instead of ending
// the process on sing's goroutine.
func TestPipeConnWrapperNilTimerBecomesError(t *testing.T) {
	w := &PipeConnWrapper{
		R: strings.NewReader("payload"),
		W: &collectWriter{},
	}

	if _, err := w.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read with a nil timer returned no error")
	}
	if _, err := w.Write([]byte("payload")); err == nil {
		t.Fatal("Write with a nil timer returned no error")
	}
}
