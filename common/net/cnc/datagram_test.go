package cnc

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// writtenLengths writes each payload to a connection over a pipe and returns
// the lengths of the buffers the pipe then holds.
func writtenLengths(t *testing.T, datagrams bool, payloads ...[]byte) []int32 {
	t.Helper()
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, _ := pipe.New(pipe.WithoutSizeLimit())
	output := ConnectionOutputMulti(downlinkReader)
	if datagrams {
		output = ConnectionOutputMultiUDP(downlinkReader)
	}
	connection := NewConnection(ConnectionInputMulti(uplinkWriter), output)
	t.Cleanup(func() { connection.Close() })
	for _, payload := range payloads {
		if n, err := connection.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("wrote %d bytes of %d: %v", n, len(payload), err)
		}
	}
	mb, err := uplinkReader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	lengths := make([]int32, 0, len(mb))
	for _, b := range mb {
		lengths = append(lengths, b.Len())
	}
	return lengths
}

// A connection for a UDP destination is a link that carries a datagram per
// buffer, and the SOCKS and Shadowsocks outbounds write their packets to it
// with Write when sockopt.dialerProxy gives them one. Write split a packet
// above buf.Size into regular buffers, which the other outbound sent as
// datagrams of their own: the rest of a SOCKS packet went on as a packet with
// a header of payload bytes. It writes such a packet as one buffer; a stream
// connection still writes regular buffers.
func TestDatagramConnectionWritesEachPacketAsOneBuffer(t *testing.T) {
	long := bytes.Repeat([]byte{1}, 9000)
	full := bytes.Repeat([]byte{2}, buf.Size)
	short := []byte("ping")
	if got := writtenLengths(t, true, long, full, short); len(got) != 3 || got[0] != 9000 || got[1] != buf.Size || got[2] != 4 {
		t.Fatalf("a datagram connection wrote buffers of %v bytes, want [9000 8192 4]", got)
	}
	if got := writtenLengths(t, false, long); len(got) != 2 || got[0] != buf.Size || got[1] != 808 {
		t.Fatalf("a stream connection wrote buffers of %v bytes, want [8192 808]", got)
	}
}
