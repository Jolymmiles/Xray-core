package buf_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	. "github.com/xtls/xray-core/common/buf"
)

// cuttingSocket returns one datagram per Read and, like a UDP socket, cuts
// one longer than the buffer it reads into, without a sign of the cut.
type cuttingSocket struct {
	datagrams [][]byte
	err       error
}

func (s *cuttingSocket) Read(p []byte) (int, error) {
	if len(s.datagrams) == 0 {
		return 0, s.err
	}
	n := copy(p, s.datagrams[0])
	s.datagrams = s.datagrams[1:]
	return n, nil
}

// A read of a UDP socket into a Buffer cut a datagram longer than Size
// without a sign, and the readers of the outbounds passed its start on as a
// datagram of its own. DatagramReader reads one byte more than a Buffer
// holds, so that it drops such a datagram and returns the next; a datagram of
// Size bytes and an empty one stay as they are.
func TestDatagramReaderDropsDatagramsLongerThanABuffer(t *testing.T) {
	sent := [][]byte{
		bytes.Repeat([]byte{1}, 100),
		bytes.Repeat([]byte{2}, Size+1),
		bytes.Repeat([]byte{3}, 9000),
		bytes.Repeat([]byte{4}, Size),
		{},
		bytes.Repeat([]byte{5}, 200),
	}
	reader := &DatagramReader{Reader: &cuttingSocket{datagrams: sent, err: io.EOF}}
	for _, want := range [][]byte{sent[0], sent[3], sent[5]} {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("reading the datagram of %d bytes: %v", len(want), err)
		}
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), want) {
			t.Fatalf("read %d bytes in %d buffers, want the datagram of %d", mb.Len(), len(mb), len(want))
		}
		ReleaseMulti(mb)
	}
	if mb, err := reader.ReadMultiBuffer(); !errors.Is(err, io.EOF) {
		ReleaseMulti(mb)
		t.Fatalf("after the datagrams: %v, want io.EOF", err)
	}
}
