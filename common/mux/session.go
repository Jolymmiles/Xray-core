package mux

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	commonsession "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
)

// ClientSessionManager allocates locally owned 16-bit session IDs.
type ClientSessionManager struct {
	mu       sync.RWMutex
	sessions map[uint16]*Session
	nextID   uint16
	count    uint64
	token    uint64
	closed   bool
}

func NewClientSessionManager() *ClientSessionManager {
	return &ClientSessionManager{sessions: make(map[uint16]*Session, 16)}
}

// NewSessionManager is kept as an internal compatibility constructor while
// call sites migrate to the explicit client/server manager split.
func NewSessionManager() *ClientSessionManager {
	return NewClientSessionManager()
}

func (m *ClientSessionManager) Closed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

func (m *ClientSessionManager) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func (m *ClientSessionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int(m.count)
}

func (m *ClientSessionManager) Allocate(strategy *ClientStrategy) *Session {
	return m.allocate(strategy, false)
}

func (m *ClientSessionManager) allocateActivating(strategy *ClientStrategy) *Session {
	return m.allocate(strategy, true)
}

func (m *ClientSessionManager) allocate(strategy *ClientStrategy, activating bool) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strategy == nil {
		strategy = &ClientStrategy{}
	}
	if m.closed || (strategy.MaxConcurrency > 0 && len(m.sessions) >= int(strategy.MaxConcurrency)) ||
		(strategy.MaxConnection > 0 && m.count >= uint64(strategy.MaxConnection)) {
		return nil
	}
	id, ok := m.allocateIDLocked()
	if !ok {
		return nil
	}
	m.count++
	m.token++
	s := &Session{ID: id, ownerToken: m.token, done: done.New(), activating: activating}
	s.onClose = m.removeSession
	m.sessions[id] = s
	return s
}

func (m *ClientSessionManager) allocateIDLocked() (uint16, bool) {
	for range 65535 {
		m.nextID++
		if m.nextID == 0 {
			m.nextID++
		}
		if _, occupied := m.sessions[m.nextID]; !occupied {
			return m.nextID, true
		}
	}
	return 0, false
}

func (m *ClientSessionManager) removeSession(session *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[session.ID]
	if found && current == session && current.ownerToken == session.ownerToken {
		delete(m.sessions, session.ID)
	}
}

func (m *ClientSessionManager) Get(id uint16) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, false
	}
	s, found := m.sessions[id]
	return s, found
}

func (m *ClientSessionManager) CloseIfNoSessionAndIdle(checkSize, checkCount int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return true
	}
	if len(m.sessions) != 0 || checkSize != 0 || checkCount != int(m.count) {
		return false
	}
	m.closed = true
	m.sessions = nil
	return true
}

func (m *ClientSessionManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = nil
	m.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close(false)
	}
	return nil
}

type serverSessionSlot struct {
	token          uint64
	session        *Session
	committing     bool
	closeRequested bool
}

// ServerSessionRegistry reserves peer-supplied IDs before dispatch.
type ServerSessionRegistry struct {
	mu        sync.RWMutex
	slots     map[uint16]serverSessionSlot
	count     uint64
	nextToken uint64
	closed    bool
}

func NewServerSessionRegistry() *ServerSessionRegistry {
	return &ServerSessionRegistry{slots: make(map[uint16]serverSessionSlot, 16)}
}

type ServerSessionReservation struct {
	registry   *ServerSessionRegistry
	id         uint16
	token      uint64
	mu         sync.Mutex
	done       bool
	committing bool
}

func (r *ServerSessionReservation) BeginCommit() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return false
	}
	if r.committing {
		return true
	}
	if !r.registry.beginCommit(r.id, r.token) {
		r.done = true
		return false
	}
	r.committing = true
	return true
}

func (r *ServerSessionReservation) Publish(session *Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done || session == nil {
		return false
	}
	if !r.committing && !r.registry.beginCommit(r.id, r.token) {
		r.done = true
		return false
	}
	r.committing = true
	r.done = true
	return r.registry.publish(r.id, r.token, session)
}

func (r *ServerSessionReservation) Abort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	r.done = true
	r.registry.abort(r.id, r.token)
}

func (r *ServerSessionRegistry) Reserve(id uint16) (*ServerSessionReservation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, false
	}
	if _, occupied := r.slots[id]; occupied {
		return nil, false
	}
	r.nextToken++
	r.count++
	r.slots[id] = serverSessionSlot{token: r.nextToken}
	return &ServerSessionReservation{registry: r, id: id, token: r.nextToken}, true
}

func (r *ServerSessionRegistry) publish(id uint16, token uint64, session *Session) bool {
	r.mu.Lock()
	slot, found := r.slots[id]
	if !found || slot.token != token || slot.session != nil || !slot.committing {
		r.mu.Unlock()
		return false
	}
	session.ID = id
	session.ownerToken = token
	session.onClose = r.removeSession
	slot.session = session
	closeRequested := slot.closeRequested
	if closeRequested {
		delete(r.slots, id)
	} else {
		r.slots[id] = slot
	}
	r.mu.Unlock()
	if closeRequested {
		_ = session.Close(false)
	}
	return true
}

func (r *ServerSessionRegistry) beginCommit(id uint16, token uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	slot, found := r.slots[id]
	if !found || slot.token != token || slot.session != nil {
		return false
	}
	slot.committing = true
	r.slots[id] = slot
	return true
}

func (r *ServerSessionRegistry) abort(id uint16, token uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	slot, found := r.slots[id]
	if found && slot.token == token && slot.session == nil {
		delete(r.slots, id)
	}
}

func (r *ServerSessionRegistry) removeSession(session *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	slot, found := r.slots[session.ID]
	if found && slot.token == session.ownerToken && slot.session == session {
		delete(r.slots, session.ID)
	}
}

func (r *ServerSessionRegistry) Get(id uint16) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, false
	}
	slot, found := r.slots[id]
	return slot.session, found && slot.session != nil
}

func (r *ServerSessionRegistry) Closed() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.closed
}

func (r *ServerSessionRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.slots)
}

func (r *ServerSessionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return int(r.count)
}

func (r *ServerSessionRegistry) CloseIfNoSessionAndIdle(checkSize, checkCount int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return true
	}
	if len(r.slots) != 0 || checkSize != 0 || checkCount != int(r.count) {
		return false
	}
	r.closed = true
	r.slots = nil
	return true
}

func (r *ServerSessionRegistry) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	sessions := make([]*Session, 0, len(r.slots))
	for id, slot := range r.slots {
		if slot.session != nil {
			sessions = append(sessions, slot.session)
			delete(r.slots, id)
		} else if slot.committing {
			slot.closeRequested = true
			r.slots[id] = slot
		} else {
			delete(r.slots, id)
		}
	}
	r.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close(false)
	}
	return nil
}

// Session represents a logical connection in a Mux carrier.
type Session struct {
	input          buf.Reader
	output         buf.Writer
	ID             uint16
	ownerToken     uint64
	onClose        func(*Session)
	transferType   protocol.TransferType
	closeOnce      sync.Once
	closed         atomic.Bool
	done           *done.Instance
	XUDP           *XUDP
	runtime        *Runtime
	xudpGeneration uint64
	xudpSink       buf.Writer
	presenceLease  commonsession.PresenceLease
	activationMu   sync.Mutex
	activating     bool
	closeRequested bool
}

func (s *Session) Close(_ bool) error {
	s.activationMu.Lock()
	if s.activating {
		s.closeRequested = true
		s.activationMu.Unlock()
		return nil
	}
	s.activationMu.Unlock()
	return s.closeNow()
}

func (s *Session) closeNow() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.presenceLease != nil {
			s.presenceLease.Close()
		}
		if s.done != nil {
			_ = s.done.Close()
		}
		if s.XUDP == nil {
			common.Interrupt(s.input)
			_ = common.Close(s.output)
		} else {
			// XUDP backend I/O belongs to the flow pumps. Closing an
			// attachment only cancels its private response sink.
			common.Interrupt(s.input)
			if s.runtime != nil {
				s.runtime.detachXUDPSession(s)
			}
		}
		if s.onClose != nil {
			s.onClose(s)
		}
	})
	return nil
}

func (s *Session) completePresenceActivation(lease commonsession.PresenceLease) {
	s.activationMu.Lock()
	if !s.activating {
		s.activationMu.Unlock()
		if lease != nil {
			lease.Close()
		}
		return
	}
	s.presenceLease = lease
	s.activating = false
	closeRequested := s.closeRequested
	s.activationMu.Unlock()
	if closeRequested {
		_ = s.closeNow()
	}
}

func (s *Session) Closed() bool {
	return s.closed.Load()
}

func (s *Session) NewReader(reader *buf.BufferedReader, dest *net.Destination) buf.Reader {
	if s.transferType == protocol.TransferTypeStream {
		return NewStreamReader(reader)
	}
	return NewPacketReader(reader, dest)
}

const (
	Initializing = 0
	Active       = 1
	Expiring     = 2
)

type XUDP struct {
	GlobalID   [8]byte
	Target     net.Destination
	Status     uint64
	Expire     time.Time
	Input      buf.Reader
	Output     buf.Writer
	Attachment *Session
	Generation uint64
	Preparing  bool
	runtime    *Runtime
	inputQueue chan xudpWriteRequest
	stop       chan struct{}
	initOnce   sync.Once
	stopOnce   sync.Once
	pumpOnce   sync.Once
	pumpWG     sync.WaitGroup
	sendMu     sync.RWMutex
	stopped    bool
}

type XUDPFlow = XUDP

func (x *XUDP) Interrupt() {
	x.interrupt()
}

type xudpKey struct {
	Principal [32]byte
	GlobalID  [8]byte
	Nonce     uint64
}
