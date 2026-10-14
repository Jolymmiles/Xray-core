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
