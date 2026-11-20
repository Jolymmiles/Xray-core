package freedom

import (
	"bytes"
	"context"
	"errors"
	stdnet "net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// readCounter counts the bytes a reader reports as read.
type readCounter struct{ value atomic.Int64 }

func (c *readCounter) Value() int64          { return c.value.Load() }
func (c *readCounter) Set(v int64) int64     { return c.value.Swap(v) }
func (c *readCounter) Add(delta int64) int64 { return c.value.Add(delta) }

// A reply longer than the reader's buffer of buf.Size bytes came out of the
// read cut to that buffer, and freedom passed its start on to the client as a
// datagram of its own. It drops the reply, on an unconnected socket and on a
// connected one, and passes on a reply that fills the buffer exactly and the
// one after; the statistics count what it passes on.
func TestPacketReaderDropsDatagramsLongerThanItsBuffer(t *testing.T) {
	sent := [][]byte{bytes.Repeat([]byte{1}, buf.Size+1), bytes.Repeat([]byte{2}, buf.Size), []byte("pong")}
	for _, c := range []struct {
		name string
		open func(t *testing.T, server *net.UDPConn, counter *readCounter) net.Conn
	}{
		{"packet conn", func(t *testing.T, server *net.UDPConn, _ *readCounter) net.Conn {
			socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { socket.Close() })
			return &net.PacketConnWrapper{PacketConn: socket, Dest: server.LocalAddr()}
		}},
		{"connected conn", func(t *testing.T, server *net.UDPConn, _ *readCounter) net.Conn {
			socket, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { socket.Close() })
			return socket
		}},
		{"connected conn with statistics", func(t *testing.T, server *net.UDPConn, counter *readCounter) net.Conn {
			socket, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { socket.Close() })
			return &stat.CounterConnection{Connection: socket, ReadCounter: counter}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })
			counter := &readCounter{}
			conn := c.open(t, server, counter)
			for _, payload := range sent {
				if _, err := server.WriteTo(payload, conn.LocalAddr()); err != nil {
					t.Fatal(err)
				}
			}
			reader := NewPacketReader(context.Background(), conn, &Handler{}, nil, net.Destination{}, net.DestinationFromAddr(server.LocalAddr()))
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, want := range sent[1:] {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatalf("waiting for the reply of %d bytes: %v", len(want), err)
				}
				got := bytes.Clone(mb[0].Bytes())
				buf.ReleaseMulti(mb)
				if !bytes.Equal(got, want) {
					t.Fatalf("passed on %d bytes of %#x, want the reply of %d bytes of %#x", len(got), got[0], len(want), want[0])
				}
			}
			if c.name == "connected conn with statistics" {
				if got, want := counter.Value(), int64(buf.Size+len("pong")); got != want {
					t.Fatalf("the statistics counted %d bytes read, want the %d passed on", got, want)
				}
			}
		})
	}
}

// ReadFrom reads as socket does, from its remote address.
func (c refusingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.socket.Read(p)
	if err != nil {
		return n, nil, err
	}
	return n, c.socket.RemoteAddr(), nil
}

// Windows fails a read that cut a datagram short with WSAEMSGSIZE, which
// net.IsMessageTooLong reports as it reports EMSGSIZE elsewhere. The reader of
// an unconnected socket returned the error, which ended the session; it drops
// that datagram and returns the next, and any other error still ends the
// session.
func TestPacketReaderSkipsTooLongErrorsOfAPacketConn(t *testing.T) {
	tooLong := &stdnet.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("wsarecvfrom", syscall.EMSGSIZE)}
	refused := &stdnet.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("wsarecvfrom", syscall.ECONNREFUSED)}
	socket := &refusingSocket{reads: []any{tooLong, []byte("pong"), tooLong, refused}}
	conn := &net.PacketConnWrapper{PacketConn: refusingPacketConn{socket: socket}, Dest: socket.RemoteAddr()}
	reader := NewPacketReader(context.Background(), conn, &Handler{}, nil, net.Destination{}, net.DestinationFromAddr(socket.RemoteAddr()))
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() = %v, want the datagram after the error", err)
	}
	if got := mb.String(); got != "pong" {
		t.Fatalf("ReadMultiBuffer() = %q, want %q", got, "pong")
	}
	buf.ReleaseMulti(mb)
	if mb, err := reader.ReadMultiBuffer(); !errors.Is(err, syscall.ECONNREFUSED) {
		buf.ReleaseMulti(mb)
		t.Fatalf("ReadMultiBuffer() = %v, want the refused connection", err)
	}
}
