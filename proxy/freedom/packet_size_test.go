package freedom

import (
	"bytes"
	"errors"
	"io"
	stdnet "net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// The inbounds hand freedom a UDP datagram whole, up to the 65535 bytes their
// framings allow, but an IP packet holds at most 65507 bytes of UDP payload
// over IPv4 and 65527 over IPv6. The socket refused a longer datagram, and
// the error ended the UDP session. Freedom drops such a datagram, as the
// proxy writers drop one they cannot frame, and sends the next whole.
func TestPacketWriterDropsDatagramsTooLongForIP(t *testing.T) {
	for _, family := range []struct {
		name    string
		ip      net.IP
		longest int
	}{
		{"IPv4", net.LocalHostIP.IP(), 65507},
		{"IPv6", net.LocalHostIPv6.IP(), 65527},
	} {
		t.Run(family.name, func(t *testing.T) {
			receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: family.ip})
			if err != nil {
				t.Skipf("no %s loopback: %v", family.name, err)
			}
			t.Cleanup(func() { receiver.Close() })
			destination := net.DestinationFromAddr(receiver.LocalAddr())

			unconnected, err := net.ListenUDP("udp", &net.UDPAddr{IP: family.ip})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { unconnected.Close() })
			connected, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { connected.Close() })

			for name, conn := range map[string]net.Conn{
				"packet conn":    &net.PacketConnWrapper{PacketConn: unconnected, Dest: receiver.LocalAddr()},
				"connected conn": connected,
			} {
				t.Run(name, func(t *testing.T) {
					sent := [][]byte{
						bytes.Repeat([]byte{1}, family.longest+1),
						bytes.Repeat([]byte{2}, family.longest),
						[]byte("ping"),
					}
					if runtime.GOOS != "linux" {
						// macOS refuses a datagram above net.inet.udp.maxdgram,
						// 9216 bytes by default, so only the drop is portable.
						sent = [][]byte{sent[0], sent[2]}
					}
					mb := make(buf.MultiBuffer, len(sent))
					for i, payload := range sent {
						mb[i] = buf.NewWithSize(int32(len(payload)))
						mb[i].Write(payload)
						udp := destination
						mb[i].UDP = &udp
					}
					writer := NewPacketWriter(conn, &Handler{}, nil, net.Destination{}, destination, nil)
					if err := writer.WriteMultiBuffer(mb); err != nil {
						t.Fatalf("WriteMultiBuffer() = %v, want the long datagram dropped", err)
					}
					received := make([]byte, 65536)
					for _, payload := range sent[1:] {
						if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
							t.Fatal(err)
						}
						n, _, err := receiver.ReadFrom(received)
						if err != nil {
							t.Fatalf("waiting for the datagram of %d bytes: %v", len(payload), err)
						}
						if !bytes.Equal(received[:n], payload) {
							t.Fatalf("received a datagram of %d bytes, want the one of %d", n, len(payload))
						}
					}
				})
			}
		})
	}
}

// errTooLong is the error of a UDP socket that refuses a datagram as too long.
var errTooLong = &stdnet.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.EMSGSIZE)}

// refusingSocket stands for a connected UDP socket. It refuses each datagram
// whose first byte has an error in refuse, with that error, and records the
// first byte of the others. Read returns the errors and datagrams of reads in
// turn, then io.EOF.
type refusingSocket struct {
	net.Conn
	refuse map[byte]error
	sent   []byte
	reads  []any
}

func (s *refusingSocket) Write(p []byte) (int, error) {
	if err := s.refuse[p[0]]; err != nil {
		return 0, err
	}
	s.sent = append(s.sent, p[0])
	return len(p), nil
}

func (s *refusingSocket) Read(p []byte) (int, error) {
	if len(s.reads) == 0 {
		return 0, io.EOF
	}
	read := s.reads[0]
	s.reads = s.reads[1:]
	if err, ok := read.(error); ok {
		return 0, err
	}
	return copy(p, read.([]byte)), nil
}

func (s *refusingSocket) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 53}
}

// refusingPacketConn is an unconnected UDP socket that sends as socket does.
type refusingPacketConn struct {
	net.PacketConn
	socket *refusingSocket
}

func (c refusingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.socket.Write(p)
}

// datagrams returns a datagram to destination for each id, which is its first
// byte.
func datagrams(destination net.Destination, ids ...byte) buf.MultiBuffer {
	mb := make(buf.MultiBuffer, len(ids))
	for i, id := range ids {
		mb[i] = buf.New()
		mb[i].Write(append([]byte{id}, bytes.Repeat([]byte{0}, 1199)...))
		udp := destination
		mb[i].UDP = &udp
	}
	return mb
}

// A socket may refuse a datagram as too long although an IP packet holds it:
// macOS refuses one above net.inet.udp.maxdgram, 9216 bytes by default, and a
// connected socket on Linux reports an ICMP "fragmentation needed", which a
// router sent for an earlier datagram, as EMSGSIZE on its next write. The
// error ended the UDP session. Freedom drops the refused datagram and sends
// the next, on a connected and on an unconnected socket; any other error
// still ends the session.
func TestPacketWriterDropsDatagramsTheSocketRefusesAsTooLong(t *testing.T) {
	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
	for name, open := range map[string]func(*refusingSocket) net.Conn{
		"connected conn": func(s *refusingSocket) net.Conn { return s },
		"packet conn": func(s *refusingSocket) net.Conn {
			return &net.PacketConnWrapper{PacketConn: refusingPacketConn{socket: s}, Dest: s.RemoteAddr()}
		},
	} {
		t.Run(name, func(t *testing.T) {
			socket := &refusingSocket{refuse: map[byte]error{2: errTooLong, 4: stdnet.ErrClosed}}
			writer := NewPacketWriter(open(socket), &Handler{}, nil, net.Destination{}, destination, nil)
			if err := writer.WriteMultiBuffer(datagrams(destination, 1, 2, 3)); err != nil {
				t.Fatalf("WriteMultiBuffer() = %v, want the refused datagram dropped", err)
			}
			if !bytes.Equal(socket.sent, []byte{1, 3}) {
				t.Fatalf("the socket sent datagrams %v, want 1 and 3", socket.sent)
			}
			if err := writer.WriteMultiBuffer(datagrams(destination, 4, 5)); !errors.Is(err, stdnet.ErrClosed) {
				t.Fatalf("WriteMultiBuffer() = %v, want the error of the closed socket", err)
			}
			if !bytes.Equal(socket.sent, []byte{1, 3}) {
				t.Fatalf("the socket sent datagrams %v after its error, want none", socket.sent[2:])
			}
		})
	}
}

// A connected socket on Linux reports the ICMP "fragmentation needed" of an
// earlier datagram on its next read as well, which ended the session while
// the reader waited for a reply. The reader skips that error and returns the
// next datagram; any other error still ends the session.
func TestPacketReaderSkipsTooLongErrorsOfAConnectedSocket(t *testing.T) {
	tooLong := &stdnet.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.EMSGSIZE)}
	refused := &stdnet.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.ECONNREFUSED)}
	socket := &refusingSocket{reads: []any{tooLong, []byte("pong"), tooLong, tooLong, refused}}
	reader := NewPacketReader(socket, &Handler{}, nil, net.Destination{}, net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53))
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
