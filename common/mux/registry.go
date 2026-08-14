package mux

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/session"
)

type sessionSlotState uint8

const (
	sessionSlotPending sessionSlotState = iota
	sessionSlotActivating
	sessionSlotActive
)

type sessionSlot struct {
	token          uint64
	state          sessionSlotState
	closeRequested bool
	cancel         context.CancelFunc
	owner          *Session
}

type sessionRegistry struct {
	mu        sync.Mutex
	slots     map[uint16]*sessionSlot
	nextToken uint64
	lifetime  uint64
	closing   bool
	commits   sync.WaitGroup
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{slots: make(map[uint16]*sessionSlot, 16)}
}

func (r *sessionRegistry) reserve(id uint16) *sessionAdmission {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reserveLocked(id)
}

func (r *sessionRegistry) reserveLocked(id uint16) *sessionAdmission {
	if r.closing || r.slots[id] != nil {
		return nil
	}
	r.nextToken++
	if r.nextToken == 0 {
		r.nextToken++
	}
	r.slots[id] = &sessionSlot{token: r.nextToken, state: sessionSlotPending}
	r.lifetime++
	return &sessionAdmission{registry: r, id: id, token: r.nextToken}
}

func (r *sessionRegistry) active(id uint16) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	slot := r.slots[id]
	if slot == nil || slot.state != sessionSlotActive || slot.owner == nil {
		return nil, false
	}
	return slot.owner, true
}

func (r *sessionRegistry) admitted() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.slots)
}

func (r *sessionRegistry) activeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, slot := range r.slots {
		if slot.state == sessionSlotActive {
			count++
		}
	}
	return count
}

func (r *sessionRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int(r.lifetime)
}

func (r *sessionRegistry) closeIfIdle(checkAdmitted, checkCount int) bool {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return true
	}
	if len(r.slots) != 0 || checkAdmitted != 0 || checkCount != int(r.lifetime) {
		r.mu.Unlock()
		return false
	}
	r.closing = true
	r.mu.Unlock()
	return true
}

func (r *sessionRegistry) isClosing() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closing
}

func (r *sessionRegistry) closeActive(id uint16, token uint64) {
	var owner *Session
	r.mu.Lock()
	if slot := r.slots[id]; slot != nil && slot.token == token && slot.state == sessionSlotActive {
		owner = slot.owner
		delete(r.slots, id)
	}
	r.mu.Unlock()
	if owner != nil {
		owner.releaseManaged()
	}
}

func (r *sessionRegistry) close() {
	var owners []*Session
	var cancels []context.CancelFunc
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		r.commits.Wait()
		return
	}
	r.closing = true
	for id, slot := range r.slots {
		if slot.cancel != nil {
			cancels = append(cancels, slot.cancel)
		}
		switch slot.state {
		case sessionSlotActivating:
			slot.closeRequested = true
		case sessionSlotActive:
			owners = append(owners, slot.owner)
			delete(r.slots, id)
		default:
			delete(r.slots, id)
		}
	}
	r.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, owner := range owners {
		owner.releaseManaged()
	}
	r.commits.Wait()
}

type sessionAdmission struct {
	registry  *sessionRegistry
	id        uint16
	token     uint64
	mu        sync.Mutex
	begun     bool
	finished  bool
	completed bool
}

func (a *sessionAdmission) prepare(cancel context.CancelFunc) bool {
	a.registry.mu.Lock()
	defer a.registry.mu.Unlock()
	slot := a.registry.slots[a.id]
	if slot == nil || slot.token != a.token || slot.closeRequested || a.registry.closing {
		return false
	}
	slot.cancel = cancel
	return true
}

func (a *sessionAdmission) beginCommit() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.begun || a.finished {
		return false
	}
	a.registry.mu.Lock()
	slot := a.registry.slots[a.id]
	if slot == nil || slot.token != a.token || slot.closeRequested || a.registry.closing {
		a.registry.mu.Unlock()
		return false
	}
	slot.state = sessionSlotActivating
	a.registry.commits.Add(1)
	a.registry.mu.Unlock()
	a.begun = true
	return true
}

func (a *sessionAdmission) finishCommit(owner *Session, lease session.PresenceLease) bool {
	a.mu.Lock()
	if !a.begun || a.finished {
		a.mu.Unlock()
		closeRejectedSession(owner, lease)
		return false
	}
	a.finished = true
	a.mu.Unlock()

	published := false
	a.registry.mu.Lock()
	slot := a.registry.slots[a.id]
	if slot != nil && slot.token == a.token && slot.state == sessionSlotActivating {
		owner.ID = a.id
		owner.ownerToken = a.token
		owner.presenceLease = lease
		owner.cancel = slot.cancel
		owner.ownerClose = a.registry.closeActive
		slot.owner = owner
		published = true
	}
	a.registry.mu.Unlock()
	if !published {
		closeRejectedSession(owner, lease)
		a.mu.Lock()
		a.completed = true
		a.mu.Unlock()
		a.registry.commits.Done()
	}
	return published
}

// completeCommit ends the authorization barrier after the caller has published
// every owner-specific resource. A close requested after beginCommit is then
// routed through the normal active-owner terminal path.
func (a *sessionAdmission) completeCommit() {
	a.mu.Lock()
	if !a.begun || !a.finished || a.completed {
		a.mu.Unlock()
		return
	}
	a.completed = true
	a.mu.Unlock()

	closeRequested := false
	a.registry.mu.Lock()
	if slot := a.registry.slots[a.id]; slot != nil && slot.token == a.token && slot.state == sessionSlotActivating && slot.owner != nil {
		slot.state = sessionSlotActive
		closeRequested = slot.closeRequested || a.registry.closing
	}
	a.registry.mu.Unlock()
	if closeRequested {
		a.registry.closeActive(a.id, a.token)
	}
	a.registry.commits.Done()
}

func (a *sessionAdmission) abort() {
	a.mu.Lock()
	if a.finished {
		a.mu.Unlock()
		return
	}
	if a.begun {
		a.mu.Unlock()
		var cancel context.CancelFunc
		a.registry.mu.Lock()
		if slot := a.registry.slots[a.id]; slot != nil && slot.token == a.token {
			slot.closeRequested = true
			cancel = slot.cancel
		}
		a.registry.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return
	}
	a.finished = true
	a.mu.Unlock()
	a.registry.mu.Lock()
	if slot := a.registry.slots[a.id]; slot != nil && slot.token == a.token {
		delete(a.registry.slots, a.id)
	}
	a.registry.mu.Unlock()
}

type clientSessionManager struct {
	registry *sessionRegistry
	nextID   uint16
}

func newClientSessionManager() *clientSessionManager {
	return &clientSessionManager{registry: newSessionRegistry()}
}

func (m *clientSessionManager) allocate(strategy *ClientStrategy) *sessionAdmission {
	m.registry.mu.Lock()
	defer m.registry.mu.Unlock()
	if m.registry.closing || strategy.MaxConcurrency > 0 && len(m.registry.slots) >= int(strategy.MaxConcurrency) || strategy.MaxConnection > 0 && m.registry.lifetime >= uint64(strategy.MaxConnection) {
		return nil
	}
	for range uint32(^uint16(0)) {
		m.nextID++
		if m.nextID == 0 {
			m.nextID++
		}
		if m.registry.slots[m.nextID] == nil {
			admission := m.registry.reserveLocked(m.nextID)
			return admission
		}
	}
	return nil
}

func (m *clientSessionManager) active(id uint16) (*Session, bool) {
	return m.registry.active(id)
}

func (m *clientSessionManager) admitted() int    { return m.registry.admitted() }
func (m *clientSessionManager) activeCount() int { return m.registry.activeCount() }
func (m *clientSessionManager) count() int       { return m.registry.count() }
func (m *clientSessionManager) close()           { m.registry.close() }
func (m *clientSessionManager) closeIfIdle(size, count int) bool {
	return m.registry.closeIfIdle(size, count)
}

func closeRejectedSession(owner *Session, lease session.PresenceLease) {
	if owner != nil {
		owner.releaseManaged()
	}
	if lease != nil {
		lease.Close()
	}
}
