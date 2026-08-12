package session

import (
	"context"
	"net/netip"
)

// PresenceSubject is the immutable authenticated identity and physical peer
// carried by a presence scope.
type PresenceSubject struct {
	Email        string
	Level        uint32
	IP           netip.Addr
	PrincipalKey [32]byte
	Reusable     bool
}

// PresenceProvider snapshots an authenticated subject from a carrier context.
type PresenceProvider interface {
	SnapshotPresence(context.Context) PresenceScope
}

// PresenceProviderSource exposes structural presence without changing the
// stable dispatcher interface.
type PresenceProviderSource interface {
	PresenceProvider() PresenceProvider
}

// PresenceClaimant identifies an outbound that structurally owns selected
// requests instead of the direct request context.
type PresenceClaimant interface {
	ClaimsPresence(context.Context) bool
}

// PresenceTracker prepares online ownership for a subject.
type PresenceTracker interface {
	Prepare(PresenceSubject) PresenceReservation
}

// PresenceReservation is a one-shot candidate for activation or handoff.
type PresenceReservation interface {
	Activate() PresenceLease
	Handoff(PresenceLease) PresenceLease
	HandoffAll([]PresenceLease) []PresenceLease
	Abort()
}

// PresenceLease owns one committed online reference.
type PresenceLease interface {
	Close()
}

// PresenceScope is an immutable authenticated subject and tracker pair. Its
// zero value is a valid no-op scope.
type PresenceScope struct {
	subject PresenceSubject
	tracker PresenceTracker
}

// NewPresenceScope returns a scope only for a complete trackable subject.
func NewPresenceScope(subject PresenceSubject, tracker PresenceTracker) PresenceScope {
	subject.IP = subject.IP.Unmap()
	if tracker == nil || subject.Email == "" || !subject.IP.IsValid() || subject.IP.IsUnspecified() || subject.IP.IsLoopback() {
		return PresenceScope{}
	}
	return PresenceScope{subject: subject, tracker: tracker}
}

// Subject returns a value copy of the captured subject.
func (s PresenceScope) Subject() PresenceSubject {
	return s.subject
}

// Prepare creates a reservation or an allocation-free no-op reservation.
func (s PresenceScope) Prepare() PresenceReservation {
	if s.tracker == nil {
		return noopPresence
	}
	reservation := s.tracker.Prepare(s.subject)
	if reservation == nil {
		return noopPresence
	}
	return reservation
}

type noopPresenceType struct{}

var noopPresence noopPresenceType

func (noopPresenceType) Activate() PresenceLease { return noopPresence }

func (noopPresenceType) Handoff(old PresenceLease) PresenceLease {
	if old != nil {
		old.Close()
	}
	return noopPresence
}

func (noopPresenceType) HandoffAll(old []PresenceLease) []PresenceLease {
	if len(old) == 0 {
		return nil
	}
	replacements := make([]PresenceLease, len(old))
	for index, lease := range old {
		if lease != nil {
			lease.Close()
		}
		replacements[index] = noopPresence
	}
	return replacements
}

func (noopPresenceType) Abort() {}
func (noopPresenceType) Close() {}

// PresenceMode selects which lifecycle owns online presence for a dispatch.
type PresenceMode uint8

const (
	PresenceModeContext PresenceMode = iota
	PresenceModeExternal
	PresenceModeUntracked
)
