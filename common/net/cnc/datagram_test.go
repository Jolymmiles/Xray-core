package cnc

import (
	"bytes"
	"fmt"
	"io"
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

// datagramLink returns its datagrams in turn, a buffer each, as many to a
// read as perRead, and then fails with io.EOF.
type datagramLink struct {
	datagrams [][]byte
	perRead   int
}

func (l *datagramLink) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(l.datagrams) == 0 {
		return nil, io.EOF
	}
	var mb buf.MultiBuffer
	for i := 0; i < l.perRead && len(l.datagrams) > 0; i++ {
		b := buf.NewWithSize(int32(len(l.datagrams[0])))
		_, _ = b.Write(l.datagrams[0])
		mb = append(mb, b)
		l.datagrams = l.datagrams[1:]
	}
	return mb, nil
}

// Read of a connection for a UDP destination copied a datagram longer than
// the buffer into it and dropped the rest without a sign, as a UDP socket
// does: a UDP mask or a QUIC transport over sockopt.dialerProxy, which read it
// through FakePacketConn, took the start of a packet for a whole one. Read
// drops such a datagram and returns the next that fits, whether the link
// returns its datagrams one or several to a read, and however many it drops
// in a row; an empty datagram is skipped with them.
func TestDatagramConnectionReadDropsDatagramsLongerThanTheBuffer(t *testing.T) {
	long := bytes.Repeat([]byte{1}, buf.Size+1)
	full := bytes.Repeat([]byte{2}, buf.Size)
	for _, perRead := range []int{1, 3, 200} {
		t.Run(fmt.Sprint(perRead, " to a read"), func(t *testing.T) {
			sent := [][]byte{long, full}
			for i := 0; i < 100; i++ {
				sent = append(sent, long)
			}
			if perRead > 1 {
				// a pipe hands on no read without bytes, so an empty
				// datagram comes with others
				sent = append(sent, nil)
			}
			sent = append(sent, []byte("pong"), long)
			connection := NewConnection(ConnectionOutputMultiUDP(&datagramLink{datagrams: sent, perRead: perRead}))
			p := make([]byte, buf.Size)
			for _, want := range [][]byte{full, []byte("pong")} {
				n, err := connection.Read(p)
				if err != nil {
					t.Fatalf("waiting for the datagram of %d bytes: %v", len(want), err)
				}
				if !bytes.Equal(p[:n], want) {
					t.Fatalf("read %d bytes of %#x, want the datagram of %d bytes of %#x", n, p[0], len(want), want[0])
				}
			}
			if n, err := connection.Read(p); n != 0 || err != io.EOF {
				t.Fatalf("read %d bytes and %v after the last datagram, want io.EOF", n, err)
			}
		})
	}
}
