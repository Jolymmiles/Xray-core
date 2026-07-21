package singmux

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type memoryConn struct {
	bytes.Buffer
}

func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestPaddingFrameGolden(t *testing.T) {
	underlying := &memoryConn{}
	conn := newPaddingConnWithGenerator(underlying, func() int { return 3 })
	if _, err := conn.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 3, 0, 3, 'a', 'b', 'c', 0, 0, 0}
	if !bytes.Equal(underlying.Bytes(), want) {
		t.Fatalf("padding frame = %x, want %x", underlying.Bytes(), want)
	}
}

func TestPaddingReaderAcceptsFragmentedReads(t *testing.T) {
	underlying := &memoryConn{}
	underlying.Write([]byte{0, 5, 0, 2})
	underlying.WriteString("hello")
	underlying.Write([]byte{0, 0})
	conn := newPaddingConnWithGenerator(underlying, func() int { return 0 })
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("payload = %q, want hello", got)
	}
}

func TestPaddingStopsAfterSixteenFrames(t *testing.T) {
	underlying := &memoryConn{}
	conn := newPaddingConnWithGenerator(underlying, func() int { return 0 })
	for i := 0; i < paddingFrameCount; i++ {
		if _, err := conn.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Write([]byte("raw")); err != nil {
		t.Fatal(err)
	}
	encoded := underlying.Bytes()
	if got := string(encoded[len(encoded)-3:]); got != "raw" {
		t.Fatalf("tail = %q, want raw", got)
	}
}

func TestPaddingReaderSwitchesToRawStream(t *testing.T) {
	underlying := &memoryConn{}
	for i := 0; i < paddingFrameCount; i++ {
		underlying.Write([]byte{0, 1, 0, 0, byte(i)})
	}
	underlying.WriteString("raw")
	conn := newPaddingConnWithGenerator(underlying, func() int { return 0 })
	got := make([]byte, paddingFrameCount+3)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got[paddingFrameCount:]) != "raw" {
		t.Fatalf("raw tail = %q", got[paddingFrameCount:])
	}
}

func TestPaddingConnDelegatesNetConnMethods(t *testing.T) {
	underlying := &memoryConn{}
	conn := newPaddingConn(underlying)
	if conn.LocalAddr() == nil || conn.RemoteAddr() == nil {
		t.Fatal("addresses must be delegated")
	}
	deadline := time.Now()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPaddingRejectsInvalidGeneratedLength(t *testing.T) {
	conn := newPaddingConnWithGenerator(&memoryConn{}, func() int { return -1 })
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("negative padding length must be rejected")
	}
}

func TestPaddingZeroLengthRead(t *testing.T) {
	conn := newPaddingConnWithGenerator(&memoryConn{}, func() int { return 0 })
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v", n, err)
	}
}
