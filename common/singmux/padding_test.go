package singmux

import (
	"bytes"
	"encoding/binary"
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

// TestPaddingFrameGolden pins the wire framing from SPEC.md:
// payload_length(2) padding_length(2) payload padding. The padding bytes
// themselves are deliberately unspecified — the peer skips padding_length
// bytes whatever they contain — so only their count is asserted here.
// TestPaddingContentIsNotConstant covers what goes into them.
func TestPaddingFrameGolden(t *testing.T) {
	underlying := &memoryConn{}
	conn := newPaddingConnWithGenerator(underlying, func() int { return 3 })
	if _, err := conn.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	frame := underlying.Bytes()
	wantHeader := []byte{0, 3, 0, 3, 'a', 'b', 'c'}
	if !bytes.Equal(frame[:len(wantHeader)], wantHeader) {
		t.Fatalf("padding frame header = %x, want %x", frame[:len(wantHeader)], wantHeader)
	}
	if got := len(frame) - len(wantHeader); got != 3 {
		t.Fatalf("padding frame carries %d padding bytes, want 3", got)
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

func TestPaddingReaderReturnsAvailablePayloadBeforeFrameCompletes(t *testing.T) {
	underlying := &memoryConn{}
	underlying.Write([]byte{0, 5, 0, 0, 'h', 'e'})
	conn := newPaddingConnWithGenerator(underlying, func() int { return 0 })

	got := make([]byte, 2)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("partial padded payload read failed: %v", err)
	}
	if n != len(got) || string(got) != "he" {
		t.Fatalf("partial padded payload = %q (%d bytes), want he", got[:n], n)
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

func TestPaddingReaderDiscardsFragmentedPaddingBeforeRawStream(t *testing.T) {
	underlying := &memoryConn{}
	for i := range paddingFrameCount {
		underlying.Write([]byte{0, 1, 0, 3, byte(i), 0xa5, 0xa5, 0xa5})
	}
	underlying.WriteByte(0x7f)
	conn := newPaddingConnWithGenerator(underlying, func() int { return 0 })

	got := make([]byte, paddingFrameCount+1)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	for i := range paddingFrameCount {
		if got[i] != byte(i) {
			t.Fatalf("payload byte %d = %x, want %x", i, got[i], byte(i))
		}
	}
	if got[paddingFrameCount] != 0x7f {
		t.Fatalf("raw tail = %x, want 7f", got[paddingFrameCount])
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

func BenchmarkPaddingRead16Frames(b *testing.B) {
	const payloadSize = 8 * 1024
	payload := bytes.Repeat([]byte{0x5a}, payloadSize)
	padding := bytes.Repeat([]byte{0xa5}, 32)
	encoded := make([]byte, 0, paddingFrameCount*(4+payloadSize+len(padding))+1)
	for range paddingFrameCount {
		encoded = binary.BigEndian.AppendUint16(encoded, payloadSize)
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(padding)))
		encoded = append(encoded, payload...)
		encoded = append(encoded, padding...)
	}
	encoded = append(encoded, 0x7f)
	var frameHeader [8]byte
	framePayload := make([]byte, payloadSize-len(frameHeader))
	var rawTail [1]byte
	b.ReportAllocs()
	b.SetBytes(int64(paddingFrameCount*payloadSize + len(rawTail)))
	for range b.N {
		underlying := &memoryConn{Buffer: *bytes.NewBuffer(encoded)}
		connection := newPaddingConnWithGenerator(underlying, func() int { return 0 })
		for range paddingFrameCount {
			if _, err := io.ReadFull(connection, frameHeader[:]); err != nil {
				b.Fatal(err)
			}
			if _, err := io.ReadFull(connection, framePayload); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := io.ReadFull(connection, rawTail[:]); err != nil {
			b.Fatal(err)
		}
		if rawTail[0] != 0x7f {
			b.Fatal("raw tail was not delivered")
		}
	}
}
