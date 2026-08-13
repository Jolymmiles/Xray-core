package hysteria

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
)

type interConn struct {
	stream       *quic.Stream
	local        net.Addr
	remote       net.Addr
	physicalPeer net.Addr

	client bool
	user   *protocol.MemoryUser
}

func (c *interConn) User() *protocol.MemoryUser {
	return c.user
}

func (c *interConn) PhysicalPeer() net.Addr {
	peer, _ := net.CopyPhysicalPeer(c.physicalPeer)
	return peer
}

func (c *interConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *interConn) Write(b []byte) (int, error) {
	if c.client {
		c.client = false
		if _, err := c.stream.Write(append(quicvarint.Append(nil, FrameTypeTCPRequest), b...)); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return c.stream.Write(b)
}

func (c *interConn) Close() error {
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *interConn) LocalAddr() net.Addr {
	return c.local
}

func (c *interConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *interConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *interConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *interConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

type InterConn struct {
	local        net.Addr
	remote       net.Addr
	physicalPeer net.Addr

	id      uint32
	ch      chan []byte
	active  atomic.Int64
	closed  atomic.Bool
	clock   *atomic.Int64
	manager *udpSessionManager

	user *protocol.MemoryUser
}

func (i *InterConn) User() *protocol.MemoryUser {
	return i.user
}

func (i *InterConn) PhysicalPeer() net.Addr {
	peer, _ := net.CopyPhysicalPeer(i.physicalPeer)
	return peer
}

func (c *InterConn) Time() time.Time {
	return time.Unix(0, c.active.Load())
}

func (c *InterConn) Update() {
	if c.clock != nil {
		c.active.Store(c.clock.Load())
		return
	}
	c.active.Store(time.Now().UnixNano())
}

func (c *InterConn) Read(p []byte) (int, error) {
	b, ok := <-c.ch
	if !ok {
		return 0, io.EOF
	}
	if len(p) < len(b) {
		return 0, io.ErrShortBuffer
	}
	c.Update()
	return copy(p, b), nil
}

func (c *InterConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	binary.BigEndian.PutUint32(p, c.id)
	var err error
	if c.manager != nil && c.manager.conn != nil {
		err = c.manager.conn.SendDatagram(p)
	} else if c.manager != nil && c.manager.send != nil {
		err = c.manager.send(p)
	} else {
		err = io.ErrClosedPipe
	}
	if err != nil {
		return 0, err
	}
	c.Update()
	return len(p), nil
}

func (c *InterConn) Close() error {
	if c.closed.Load() {
		return nil
	}
	if c.manager != nil {
		c.manager.Lock()
		c.manager.close(c)
		c.manager.Unlock()
	} else {
		c.closed.Store(true)
	}
	return nil
}

func (c *InterConn) LocalAddr() net.Addr {
	return c.local
}

func (c *InterConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *InterConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *InterConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *InterConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type udpSessionManager struct {
	sync.RWMutex

	conn   *quic.Conn
	m      map[uint32]*InterConn
	next   uint32
	closed atomic.Bool
	clock  atomic.Int64

	addConn        internet.ConnHandler
	udpIdleTimeout time.Duration
	user           *protocol.MemoryUser
	physicalPeer   net.Addr
	send           func([]byte) error
}

const initialUDPSessionCapacity = 16

func newUDPSessionMap() map[uint32]*InterConn {
	return make(map[uint32]*InterConn, initialUDPSessionCapacity)
}

func (m *udpSessionManager) close(udpConn *InterConn) {
	if udpConn.closed.CompareAndSwap(false, true) {
		close(udpConn.ch)
		delete(m.m, udpConn.id)
	}
}

func (m *udpSessionManager) clean() {
	ticker := time.NewTicker(idleCleanupInterval)
	defer ticker.Stop()
	m.clock.Store(time.Now().UnixNano())

	for range ticker.C {
		if m.isClosed() {
			return
		}
		now := time.Now()
		m.clock.Store(now.UnixNano())
		m.cleanInactive(now)
	}
}

func (m *udpSessionManager) cleanInactive(now time.Time) {
	m.Lock()
	activeBefore := now.UnixNano() - m.udpIdleTimeout.Nanoseconds()
	for _, udpConn := range m.m {
		if udpConn.active.Load() < activeBefore {
			m.close(udpConn)
		}
	}
	m.Unlock()
}

func (m *udpSessionManager) isClosed() bool {
	return m.closed.Load()
}

func (m *udpSessionManager) run() {
	for {
		d, err := m.conn.ReceiveDatagram(context.Background())
		if err != nil {
			break
		}

		if len(d) < 4 {
			continue
		}
		id := binary.BigEndian.Uint32(d[:4])

		m.feed(id, d)
	}

	m.Lock()
	defer m.Unlock()

	m.closed.Store(true)

	for _, udpConn := range m.m {
		m.close(udpConn)
	}
}

func (m *udpSessionManager) udp() (*InterConn, error) {
	m.Lock()
	defer m.Unlock()

	if m.closed.Load() {
		return nil, errors.New("closed")
	}

	udpConn := &InterConn{
		local:        m.conn.LocalAddr(),
		remote:       m.conn.RemoteAddr(),
		physicalPeer: m.physicalPeer,

		id:      m.next,
		ch:      make(chan []byte, udpMessageChanSize),
		manager: m,
	}
	m.m[m.next] = udpConn
	m.next++

	return udpConn, nil
}

func (m *udpSessionManager) dispatchConnection(udpConn *InterConn) {
	// A handler owns the connection until processing ends, which for UDP may be the idle timeout.
	go m.addConn(udpConn)
}

func (m *udpSessionManager) feed(id uint32, d []byte) {
	m.RLock()
	udpConn, ok := m.m[id]
	if ok {
		select {
		case udpConn.ch <- d:
		default:
		}
		m.RUnlock()
		return
	}
	m.RUnlock()

	if m.addConn == nil {
		return
	}

	m.Lock()
	udpConn, ok = m.m[id]
	created := !ok
	if !ok {
		udpConn = &InterConn{
			local:        m.conn.LocalAddr(),
			remote:       m.conn.RemoteAddr(),
			physicalPeer: m.physicalPeer,

			id:      id,
			ch:      make(chan []byte, udpMessageChanSize),
			manager: m,
		}
		udpConn.clock = &m.clock
		udpConn.Update()
		udpConn.user = m.user
		m.m[id] = udpConn
	}

	select {
	case udpConn.ch <- d:
	default:
	}
	m.Unlock()

	if created {
		m.dispatchConnection(udpConn)
	}
}
