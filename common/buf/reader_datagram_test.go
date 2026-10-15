package buf_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	. "github.com/xtls/xray-core/common/buf"
)

// arrivingStream hands out its bytes one at a time, as a peer's bytes arrive,
// and records the largest buffer a reader offered for them.
type arrivingStream struct {
	bytes   *bytes.Reader
	largest int
}

func (s *arrivingStream) Read(p []byte) (int, error) {
	s.largest = max(s.largest, cap(p))
	return s.bytes.Read(p[:min(len(p), 1)])
}

// datagramOf returns size bytes that differ from one Buffer of Size bytes to
// the next.
func datagramOf(size int32) []byte {
	datagram := make([]byte, size)
	for i := range datagram {
		datagram[i] = byte(i % 251)
	}
	return datagram
}

// ReadDatagram returns a datagram whole, in one Buffer, and takes memory as
// its bytes arrive: until the last one, it reads them into Buffers of Size
// bytes, so that a peer that announces a long datagram and stalls holds no
// more memory than it sent.
func TestReadDatagramTakesMemoryAsTheBytesArrive(t *testing.T) {
	for _, size := range []int32{0, 1, Size - 1, Size, Size + 1, 2 * Size, 2*Size + 1, 9000, 65535} {
		datagram := datagramOf(size)
		stream := &arrivingStream{bytes: bytes.NewReader(datagram)}
		b, err := ReadDatagram(stream, size)
		if err != nil {
			t.Fatalf("ReadDatagram(%d) = %v", size, err)
		}
		if !bytes.Equal(b.Bytes(), datagram) {
			t.Fatalf("ReadDatagram(%d) returned %d bytes other than the datagram", size, b.Len())
		}
		b.Release()
		if stream.largest > Size {
			t.Fatalf("a datagram of %d bytes was read into a buffer of %d bytes before it arrived, want at most %d", size, stream.largest, Size)
		}
	}
}

// ReadDatagram reads no byte past the datagram, so the next one follows.
func TestReadDatagramLeavesTheStreamAtTheNextDatagram(t *testing.T) {
	first, second := datagramOf(2*Size+1), []byte("next")
	stream := bytes.NewReader(append(bytes.Clone(first), second...))
	for _, want := range [][]byte{first, second} {
		b, err := ReadDatagram(stream, int32(len(want)))
		if err != nil {
			t.Fatalf("ReadDatagram(%d) = %v", len(want), err)
		}
		if !bytes.Equal(b.Bytes(), want) {
			t.Fatalf("ReadDatagram(%d) returned %d bytes other than the datagram", len(want), b.Len())
		}
		b.Release()
	}
}

// A stream that ends inside a datagram ends it with io.ErrUnexpectedEOF, as
// io.ReadFull does, also where the bytes that arrived fill whole Buffers;
// io.EOF means that no byte of it arrived. Any other error of the stream comes
// back as it is.
func TestReadDatagramReportsAStreamThatEndsInside(t *testing.T) {
	for _, c := range []struct {
		size    int32
		arrived int32
		want    error
	}{
		{100, 0, io.EOF},
		{100, 99, io.ErrUnexpectedEOF},
		{Size + 100, 0, io.EOF},
		{Size + 100, 100, io.ErrUnexpectedEOF},
		{Size + 100, Size, io.ErrUnexpectedEOF},
		{65535, 7 * Size, io.ErrUnexpectedEOF},
		{65535, 65534, io.ErrUnexpectedEOF},
	} {
		b, err := ReadDatagram(bytes.NewReader(datagramOf(c.arrived)), c.size)
		if err != c.want || b != nil {
			t.Fatalf("ReadDatagram(%d) after %d bytes = %v, %v; want nil, %v", c.size, c.arrived, b, err, c.want)
		}
	}
	failure := errors.New("connection reset")
	for _, size := range []int32{100, Size + 100} {
		stream := io.MultiReader(bytes.NewReader(datagramOf(size/2)), iotest.ErrReader(failure))
		if b, err := ReadDatagram(stream, size); !errors.Is(err, failure) || b != nil {
			t.Fatalf("ReadDatagram(%d) on a failing stream = %v, %v; want nil, %v", size, b, err, failure)
		}
	}
}
