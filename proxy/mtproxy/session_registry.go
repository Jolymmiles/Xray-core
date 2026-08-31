package mtproxy

import "sync"

type secretRuntime struct {
	secret      [16]byte
	fingerprint SecretFingerprint

	mu       sync.Mutex
	revoked  bool
	sessions map[uint64]func()
}

// RegisterSession attaches a logical client to a secret. It returns false for
// unknown, duplicate, or already revoked registrations. The returned function
// is idempotent and removes the session without closing it.
func (r *SecretRegistry) RegisterSession(fingerprint SecretFingerprint, sessionID uint64, closeSession func()) (func(), bool) {
	if closeSession == nil {
		return nil, false
	}

	r.mu.Lock()
	runtime, found := r.byID[fingerprint]
	if !found {
		r.mu.Unlock()
		return nil, false
	}
	unregister, ok := runtime.register(sessionID, closeSession)
	r.mu.Unlock()
	return unregister, ok
}

func (r *secretRuntime) register(sessionID uint64, closeSession func()) (func(), bool) {
	if closeSession == nil {
		return nil, false
	}

	r.mu.Lock()
	if r.revoked {
		r.mu.Unlock()
		return nil, false
	}
	if r.sessions == nil {
		r.sessions = make(map[uint64]func())
	}
	if _, exists := r.sessions[sessionID]; exists {
		r.mu.Unlock()
		return nil, false
	}
	r.sessions[sessionID] = closeSession
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() { r.unregister(sessionID) })
	}, true
}

func (r *secretRuntime) unregister(sessionID uint64) {
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()
}

func (r *secretRuntime) revoke() ([]func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.revoked {
		return nil, false
	}
	r.revoked = true
	closers := make([]func(), 0, len(r.sessions))
	for _, closeSession := range r.sessions {
		closers = append(closers, closeSession)
	}
	r.sessions = nil
	return closers, true
}
