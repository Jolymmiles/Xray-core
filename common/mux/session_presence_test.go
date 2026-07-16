package mux

import (
	"sync"
	"sync/atomic"
	"testing"
)

type countingPresenceLease struct {
	closed atomic.Int32
}

func (l *countingPresenceLease) Close() { l.closed.Add(1) }

func TestSessionClosesPresenceLeaseOnce(t *testing.T) {
	lease := new(countingPresenceLease)
	session := &Session{presenceLease: lease}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = session.Close(false)
		}()
	}
	wg.Wait()
	if got := lease.closed.Load(); got != 1 {
		t.Fatalf("presence lease Close calls = %d; want 1", got)
	}
}

func TestServerReservationCompletesAuthorizedCommitDuringShutdown(t *testing.T) {
	registry := NewServerSessionRegistry()
	reservation, ok := registry.Reserve(11)
	if !ok || !reservation.BeginCommit() {
		t.Fatal("failed to authorize commit")
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	lease := new(countingPresenceLease)
	if !reservation.Publish(&Session{ID: 11, presenceLease: lease}) {
		t.Fatal("authorized commit was rolled back by shutdown")
	}
	if got := lease.closed.Load(); got != 1 {
		t.Fatalf("close-requested committed lease Close calls = %d; want 1", got)
	}
}

func TestClientPresenceActivationHonorsConcurrentShutdown(t *testing.T) {
	manager := NewClientSessionManager()
	session := manager.allocateActivating(&ClientStrategy{})
	if session == nil {
		t.Fatal("activating allocation failed")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	lease := new(countingPresenceLease)
	session.completePresenceActivation(lease)
	if got := lease.closed.Load(); got != 1 {
		t.Fatalf("lease Close calls after activation/shutdown race = %d; want 1", got)
	}
	if !session.Closed() {
		t.Fatal("session remained open after close-requested activation")
	}
}
