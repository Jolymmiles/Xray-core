package encoding_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

// VLESS frames each datagram of a UDP request after its 2-byte length. A peer
// may send one above buf.Size, which Xray's writer does not, and up to 65535
// bytes. The reader split it over buffers of buf.Size bytes, which the
// outbound sent as datagrams of their own; it must keep every datagram whole,
// one per read.
func TestLengthPacketReaderKeepsLargeDatagramsWhole(t *testing.T) {
	datagrams := [][]byte{
		bytes.Repeat([]byte{1}, 9000),
		bytes.Repeat([]byte{2}, 100),
		bytes.Repeat([]byte{3}, buf.Size),
		bytes.Repeat([]byte{4}, buf.Size+1),
		bytes.Repeat([]byte{5}, 200),
		bytes.Repeat([]byte{6}, 65535), // the largest length
	}
	var stream bytes.Buffer
	for _, datagram := range datagrams {
		stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(datagram))))
		stream.Write(datagram)
	}

	reader := encoding.NewLengthPacketReader(&stream)
	var got [][]byte
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			if errors.Cause(err) != io.EOF {
				t.Fatalf("after %d datagrams: %v", len(got), err)
			}
			break
		}
		if len(mb) != 1 {
			t.Fatalf("read %d buffers holding %d bytes, want one datagram", len(mb), mb.Len())
		}
		got = append(got, bytes.Clone(mb[0].Bytes()))
		buf.ReleaseMulti(mb)
	}
	if len(got) != len(datagrams) {
		t.Fatalf("read %d datagrams, want %d", len(got), len(datagrams))
	}
	for i := range datagrams {
		if !bytes.Equal(got[i], datagrams[i]) {
			t.Fatalf("datagram %d holds %d bytes other than the %d sent", i, len(got[i]), len(datagrams[i]))
		}
	}
}

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

// A peer sends the length of a datagram before its bytes and may stall in
// between. The reader took a buffer of the datagram's size, up to 128 KiB,
// as soon as the length arrived. It must read the bytes into buffers of
// buf.Size as they arrive, so that a stalled peer holds no more memory than it
// sent, and still return the datagram whole.
func TestLengthPacketReaderTakesMemoryAsTheDatagramArrives(t *testing.T) {
	for _, size := range []int{buf.Size, buf.Size + 1, 9000, 65535} {
		datagram := make([]byte, size)
		for i := range datagram {
			datagram[i] = byte(i % 251)
		}
		stream := &arrivingStream{bytes: bytes.NewReader(append(binary.BigEndian.AppendUint16(nil, uint16(size)), datagram...))}
		mb, err := encoding.NewLengthPacketReader(stream).ReadMultiBuffer()
		if err != nil {
			t.Fatalf("reading a datagram of %d bytes: %v", size, err)
		}
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), datagram) {
			t.Fatalf("read %d buffers of %d bytes, want the datagram of %d bytes whole", len(mb), mb.Len(), size)
		}
		buf.ReleaseMulti(mb)
		if stream.largest > buf.Size {
			t.Fatalf("a datagram of %d bytes was read into a buffer of %d bytes before it arrived, want at most %d", size, stream.largest, buf.Size)
		}
	}
}
