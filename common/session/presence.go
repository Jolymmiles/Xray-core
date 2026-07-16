package session

import (
	"context"
	"net/netip"
)

// PresenceMode defines who owns online presence for an internal dispatch path.
type PresenceMode uint8

const (
	PresenceModeLegacy PresenceMode = iota
	PresenceModeStructural
	PresenceModeUntracked
)

// PresenceSubject is an immutable, authenticated online-presence identity.
type PresenceSubject struct {
	Email        string
	Level        uint32
	IP           netip.Addr
	PrincipalKey [32]byte
	Reusable     bool
}

func (s PresenceSubject) Valid() bool {
	return s.Email != "" && s.IP.IsValid()
}

// PresenceLease owns one committed online reference. Close is idempotent.
type PresenceLease interface {
	Close()
}

// PresenceReservation owns candidate resources until activation or abort.
type PresenceReservation interface {
	Activate() PresenceLease
	Handoff(PresenceLease) PresenceLease
	Abort()
}

// PresenceTracker prepares leases without coupling mux to dispatcher or stats.
type PresenceTracker interface {
	Prepare(PresenceSubject) PresenceReservation
}

// PresenceScope is captured once from an authenticated physical carrier.
type PresenceScope struct {
	Subject PresenceSubject
	Tracker PresenceTracker
}

func (s PresenceScope) Prepare() PresenceReservation {
	if s.Tracker == nil || !s.Subject.Valid() {
		return NoopPresenceReservation()
	}
	return s.Tracker.Prepare(s.Subject)
}

// PresenceProvider snapshots authenticated presence state from a carrier.
type PresenceProvider interface {
	SnapshotPresence(context.Context) PresenceScope
}

type noopPresence struct{}

func (noopPresence) Close() {}

func (noopPresence) Activate() PresenceLease { return noopPresence{} }
func (noopPresence) Handoff(previous PresenceLease) PresenceLease {
	if previous != nil {
		previous.Close()
	}
	return noopPresence{}
}
func (noopPresence) Abort() {}

// NoopPresenceReservation returns a safe reservation for untracked paths.
func NoopPresenceReservation() PresenceReservation {
	return noopPresence{}
}
