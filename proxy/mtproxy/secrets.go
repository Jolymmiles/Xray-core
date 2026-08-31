package mtproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var ErrSecretCapacity = errors.New("mtproxy: client secret capacity reached")

// SecretFingerprint is a stable, non-secret identifier used by management and
// revocation paths. The raw client secret must never be logged.
type SecretFingerprint [sha256.Size]byte

func (f SecretFingerprint) String() string {
	return hex.EncodeToString(f[:])
}

func SecretFingerprintFromSecret(secret [16]byte) SecretFingerprint {
	return SecretFingerprint(sha256.Sum256(secret[:]))
}

type secretCandidate struct {
	secret      [16]byte
	fingerprint SecretFingerprint
	runtime     *secretRuntime
}

type secretSnapshot struct {
	entries []secretCandidate
}

// SecretRegistry owns the current authentication set. Handshakes read an
// immutable snapshot without taking the mutation lock. Add and Delete publish a
// complete new snapshot; the configured limit keeps that copy bounded.
type SecretRegistry struct {
	max int

	mu       sync.Mutex
	byID     map[SecretFingerprint]*secretRuntime
	snapshot atomic.Pointer[secretSnapshot]
}

func NewSecretRegistry(maxSecrets int) (*SecretRegistry, error) {
	if maxSecrets <= 0 {
		return nil, fmt.Errorf("mtproxy: invalid client secret capacity %d", maxSecrets)
	}
	registry := &SecretRegistry{
		max:  maxSecrets,
		byID: make(map[SecretFingerprint]*secretRuntime, maxSecrets),
	}
	registry.snapshot.Store(&secretSnapshot{})
	return registry, nil
}

// Add publishes a secret at the front of the candidate order. Duplicate adds
// are idempotent and return added=false.
func (r *SecretRegistry) Add(secret [16]byte) (SecretFingerprint, bool, error) {
	fingerprint := SecretFingerprintFromSecret(secret)

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, found := r.byID[fingerprint]; found {
		return fingerprint, false, nil
	}
	if len(r.byID) >= r.max {
		return SecretFingerprint{}, false, ErrSecretCapacity
	}

	runtime := &secretRuntime{
		secret:      secret,
		fingerprint: fingerprint,
	}
	current := r.snapshot.Load()
	entries := make([]secretCandidate, 1, len(current.entries)+1)
	entries[0] = secretCandidate{secret: secret, fingerprint: fingerprint, runtime: runtime}
	entries = append(entries, current.entries...)

	r.byID[fingerprint] = runtime
	r.snapshot.Store(&secretSnapshot{entries: entries})
	return fingerprint, true, nil
}

// Delete immediately revokes the secret. New or old-snapshot registrations are
// rejected before the method invokes every captured session close callback.
// Callbacks run without registry or runtime locks held.
func (r *SecretRegistry) Delete(fingerprint SecretFingerprint) bool {
	r.mu.Lock()
	runtime, found := r.byID[fingerprint]
	if !found {
		r.mu.Unlock()
		return false
	}

	closers, _ := runtime.revoke()
	delete(r.byID, fingerprint)

	current := r.snapshot.Load()
	entries := make([]secretCandidate, 0, len(current.entries)-1)
	for _, candidate := range current.entries {
		if candidate.runtime != runtime {
			entries = append(entries, candidate)
		}
	}
	r.snapshot.Store(&secretSnapshot{entries: entries})
	r.mu.Unlock()

	for _, closeSession := range closers {
		closeSession()
	}
	return true
}

func (r *SecretRegistry) Len() int {
	return len(r.snapshot.Load().entries)
}

// List returns fingerprints in current authentication order. It never exposes
// raw secret bytes.
func (r *SecretRegistry) List() []SecretFingerprint {
	entries := r.snapshot.Load().entries
	result := make([]SecretFingerprint, len(entries))
	for i := range entries {
		result[i] = entries[i].fingerprint
	}
	return result
}

// candidates returns a read-only immutable view for a single handshake. A view
// may outlive deletion; its runtime registration check is the revocation fence.
func (r *SecretRegistry) candidates() []secretCandidate {
	return r.snapshot.Load().entries
}
