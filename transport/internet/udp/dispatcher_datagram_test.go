package udp_test

import (
	"bytes"
	"context"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	. "github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

// dialDispatcherLink returns the packet connection of DialDispatcher, as
// core.DialUDP gives it, with the ends of its link that an outbound holds:
// the reader of what the connection writes and the writer of what it reads.
func dialDispatcherLink(t *testing.T) (gonet.PacketConn, *pipe.Reader, *pipe.Writer) {
	t.Helper()
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	dispatcher := &TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := DialDispatcher(ctx, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		conn.Close()
		downlinkWriter.Close()
		uplinkReader.Interrupt()
	})
	return conn, uplinkReader, downlinkWriter
}

// The packet connection of DialDispatcher copied what it was written into a
// regular buffer: of a datagram above buf.Size it dispatched the first 8192
// bytes as a whole one and reported a short write without an error. It
// dispatches the datagram in one buffer of its size.
func TestDispatcherConnWritesDatagramsWhole(t *testing.T) {
	conn, uplinkReader, _ := dialDispatcherLink(t)
	destination := &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: 53}
	for _, payload := range [][]byte{bytes.Repeat([]byte{1}, 9000), bytes.Repeat([]byte{2}, buf.Size), []byte("ping")} {
		n, err := conn.WriteTo(payload, destination)
		if err != nil || n != len(payload) {
			t.Fatalf("wrote %d bytes of a datagram of %d: %v", n, len(payload), err)
		}
		mb, err := uplinkReader.ReadMultiBufferTimeout(5 * time.Second)
		if err != nil {
			t.Fatalf("waiting for the datagram of %d bytes: %v", len(payload), err)
		}
		lengths := make([]int32, 0, len(mb))
		for _, b := range mb {
			lengths = append(lengths, b.Len())
		}
		whole := len(mb) == 1 && bytes.Equal(mb[0].Bytes(), payload)
		buf.ReleaseMulti(mb)
		if !whole {
			t.Fatalf("dispatched buffers of %v bytes, want the datagram of %d bytes whole", lengths, len(payload))
		}
	}
}

// ReadFrom copied the start of a reply longer than the buffer into it and
// dropped the rest without a sign, as a UDP socket does. It drops such a
// reply and returns the next.
func TestDispatcherConnDropsRepliesLongerThanTheRead(t *testing.T) {
	conn, _, downlinkWriter := dialDispatcherLink(t)
	// the dispatcher reads replies only once a datagram has opened the link
	if _, err := conn.WriteTo([]byte("ping"), &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	sent := [][]byte{bytes.Repeat([]byte{1}, buf.Size+1), bytes.Repeat([]byte{2}, buf.Size), []byte("pong")}
	for _, reply := range sent {
		b := buf.NewWithSize(int32(len(reply)))
		_, _ = b.Write(reply)
		if err := downlinkWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
	}
	type read struct {
		payload []byte
		err     error
	}
	p := make([]byte, buf.Size)
	for _, want := range sent[1:] {
		done := make(chan read, 1)
		go func() {
			n, _, err := conn.ReadFrom(p)
			done <- read{bytes.Clone(p[:n]), err}
		}()
		select {
		case got := <-done:
			if got.err != nil {
				t.Fatalf("waiting for the reply of %d bytes: %v", len(want), got.err)
			}
			if !bytes.Equal(got.payload, want) {
				t.Fatalf("read %d bytes of %#x, want the reply of %d bytes of %#x", len(got.payload), got.payload[0], len(want), want[0])
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no reply of %d bytes within 5s", len(want))
		}
	}
}
