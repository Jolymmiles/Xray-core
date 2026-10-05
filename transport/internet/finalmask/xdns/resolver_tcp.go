package xdns

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type TCPResolver struct {
	dest   net.Destination
	dialer *finalmask.Dialer

	conn    net.Conn
	udpAddr atomic.Pointer[net.UDPAddr]

	readCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	// writeMu keeps frames whole without holding mu, so Close can interrupt
	// a write stalled on a peer that stopped reading.
	writeMu sync.Mutex
}

func NewTCPResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	dest, err := net.ParseDestination("tcp:" + config.Addr)
	if err != nil {
		return nil, err
	}
	r := &TCPResolver{
		dest:    dest,
		dialer:  dialer,
		readCh:  make(chan []byte),
		closeCh: make(chan struct{}),
	}
	if err := r.dial(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (r *TCPResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *TCPResolver) dial() error {
	if r.closed() {
		return errors.New("closed")
	}
	if r.conn != nil {
		return nil
	}
	conn, err := r.dialer.DialTCP(r.dest)
	if err != nil {
		return err
	}
	r.conn = conn
	tcpAddr := conn.RemoteAddr().(*net.TCPAddr)
	r.udpAddr.Store(&net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port})
	r.wg.Add(1)
	go r.recv(conn)
	return nil
}

func (r *TCPResolver) recv(conn net.Conn) {
	defer r.wg.Done()

	var buf [4096]byte
	for {
		_, err := io.ReadFull(conn, buf[:2])
		if err != nil {
			break
		}
		n := binary.BigEndian.Uint16(buf[:2])
		if n == 0 || n > 4096 {
			io.CopyN(io.Discard, conn, int64(n))
			continue
		}
		_, err = io.ReadFull(conn, buf[:n])
		if err != nil {
			break
		}
		p := pool4K.Get().([]byte)
		copy(p, buf[:n])
		select {
		case <-r.closeCh:
			pool4K.Put(p[:cap(p)])
		case r.readCh <- p[:n]:
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	_ = conn.Close()
	if r.conn == conn {
		r.conn = nil
	}
}

func (r *TCPResolver) Addr() *net.UDPAddr {
	return r.udpAddr.Load()
}

func (r *TCPResolver) Read(p []byte) (n int, err error) {
	packet, ok := <-r.readCh
	if ok {
		n = copy(p, packet)
		pool4K.Put(packet[:cap(packet)])
		return n, nil
	}
	return 0, io.ErrClosedPipe
}

func (r *TCPResolver) Send(p []byte) {
	r.mu.Lock()
	if r.dial() != nil {
		r.mu.Unlock()
		return
	}
	conn := r.conn
	r.mu.Unlock()

	// DNS over TCP prefixes each message with its length (RFC 1035 4.2.2).
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame, uint16(len(p)))
	copy(frame[2:], p)
	r.writeMu.Lock()
	_, err := conn.Write(frame)
	r.writeMu.Unlock()
	if err != nil {
		// recv sees the closed conn and resets it, so the next Send redials.
		_ = conn.Close()
	}
}

func (r *TCPResolver) Close() {
	r.mu.Lock()
	if r.closed() {
		r.mu.Unlock()
		return
	}
	close(r.closeCh)
	conn := r.conn
	r.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	r.wg.Wait()
	close(r.readCh)
}
