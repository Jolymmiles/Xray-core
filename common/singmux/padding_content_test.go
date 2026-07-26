// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"
)

// bufferConn is a minimal net.Conn that records everything written to it and
// replays a fixed script on read.
type bufferConn struct {
	net.Conn
	written bytes.Buffer
	read    bytes.Reader
}

func (c *bufferConn) Write(p []byte) (int, error) { return c.written.Write(p) }
func (c *bufferConn) Read(p []byte) (int, error)  { return c.read.Read(p) }
func (c *bufferConn) Close() error                { return nil }
func (c *bufferConn) SetDeadline(time.Time) error { return nil }

// TestPaddingContentIsNotConstant pins the point of the padding layer. The
// frame header already tells an observer how many padding bytes follow; if
// those bytes are a constant run, the padding contributes a recognisable
// pattern instead of hiding one. Only the length is meant to be the secret.
func TestPaddingContentIsNotConstant(t *testing.T) {
	const paddingSize = 64

	conn := &bufferConn{}
	padded := newPaddingConnWithGenerator(conn, func() int { return paddingSize })

	payload := []byte("hello")
	if _, err := padded.Write(payload); err != nil {
		t.Fatalf("write through padding conn: %v", err)
	}

	frame := conn.written.Bytes()
	wantLen := 4 + len(payload) + paddingSize
	if len(frame) != wantLen {
		t.Fatalf("frame length = %d, want %d", len(frame), wantLen)
	}

	padding := frame[4+len(payload):]
	if allEqual(padding) {
		t.Fatalf("padding is a constant run of %#02x across %d bytes", padding[0], len(padding))
	}
}

// TestPaddingContentDiffersBetweenFrames guards against a fixed pad pattern
// that varies within a frame but repeats across frames.
func TestPaddingContentDiffersBetweenFrames(t *testing.T) {
	const paddingSize = 64

	capture := func() []byte {
		conn := &bufferConn{}
		padded := newPaddingConnWithGenerator(conn, func() int { return paddingSize })
		if _, err := padded.Write([]byte("x")); err != nil {
			t.Fatalf("write through padding conn: %v", err)
		}
		frame := conn.written.Bytes()
		return append([]byte(nil), frame[5:]...)
	}

	if first, second := capture(), capture(); bytes.Equal(first, second) {
		t.Fatal("two independent frames produced identical padding bytes")
	}
}

// TestPaddingRoundTrip proves the reader still recovers the exact payload once
// the padding carries real bytes.
func TestPaddingRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("first"),
		[]byte("second chunk"),
		bytes.Repeat([]byte("z"), 5000),
	}

	conn := &bufferConn{}
	writer := newPaddingConnWithGenerator(conn, func() int { return 32 })
	var want []byte
	for _, payload := range payloads {
		if _, err := writer.Write(payload); err != nil {
			t.Fatalf("write through padding conn: %v", err)
		}
		want = append(want, payload...)
	}

	replay := &bufferConn{read: *bytes.NewReader(conn.written.Bytes())}
	reader := newPaddingConnWithGenerator(replay, func() int { return 32 })

	got := make([]byte, 0, len(want))
	chunk := make([]byte, 512)
	for len(got) < len(want) {
		n, err := reader.Read(chunk)
		if err != nil {
			t.Fatalf("read through padding conn after %d/%d bytes: %v", len(got), len(want), err)
		}
		if n == 0 {
			t.Fatalf("read returned 0 bytes after %d/%d", len(got), len(want))
		}
		got = append(got, chunk[:n]...)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("round trip corrupted the payload: got %d bytes, want %d", len(got), len(want))
	}
}

func allEqual(values []byte) bool {
	for _, value := range values {
		if value != values[0] {
			return false
		}
	}
	return true
}

func BenchmarkPaddingConnWrite(b *testing.B) {
	sizes := []int{64, 1024, 16384}
	payload := bytes.Repeat([]byte("p"), 16384)

	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				conn := &bufferConn{}
				padded := newPaddingConnWithGenerator(conn, func() int { return 128 })
				if _, err := padded.Write(payload[:size]); err != nil {
					b.Fatalf("write: %v", err)
				}
			}
		})
	}
}

func sizeName(size int) string {
	if size >= 1024 {
		return strconv.Itoa(size/1024) + "KiB"
	}
	return strconv.Itoa(size) + "B"
}
