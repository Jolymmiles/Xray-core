package mux_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/mux"
)

func TestClientSessionManagerAllocatesOnlyFreeIDsAcrossWrap(t *testing.T) {
	manager := NewClientSessionManager()
	strategy := &ClientStrategy{}
	seen := make(map[uint16]struct{})
	for range 70000 {
		session := manager.Allocate(strategy)
		if session == nil {
			t.Fatal("allocator exhausted despite every previous ID being released")
		}
		if session.ID == 0 {
			t.Fatal("allocator returned reserved SessionID 0")
		}
		seen[session.ID] = struct{}{}
		if err := session.Close(false); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 65535 {
		t.Fatalf("allocator visited %d IDs; want 65535", len(seen))
	}
	if manager.Size() != 0 || manager.Count() != 70000 {
		t.Fatalf("manager size/count = %d/%d; want 0/70000", manager.Size(), manager.Count())
	}
}

func TestClientSessionManagerHonorsLimitsAndIdleClose(t *testing.T) {
	manager := NewClientSessionManager()
	strategy := &ClientStrategy{MaxConcurrency: 1, MaxConnection: 2}
	first := manager.Allocate(strategy)
	if first == nil {
		t.Fatal("first allocation failed")
	}
	if manager.Allocate(strategy) != nil {
		t.Fatal("manager exceeded MaxConcurrency")
	}
	if err := first.Close(false); err != nil {
		t.Fatal(err)
	}
	second := manager.Allocate(strategy)
	if second == nil {
		t.Fatal("second allocation failed")
	}
	if err := second.Close(false); err != nil {
		t.Fatal(err)
	}
	if manager.Allocate(strategy) != nil {
		t.Fatal("manager exceeded MaxConnection")
	}
	if !manager.CloseIfNoSessionAndIdle(0, manager.Count()) {
		t.Fatal("idle manager did not close")
	}
}

func TestServerSessionRegistryRejectsDuplicateAndStaleReservation(t *testing.T) {
	registry := NewServerSessionRegistry()
	firstReservation, ok := registry.Reserve(7)
	if !ok {
		t.Fatal("first reservation failed")
	}
	if _, ok := registry.Reserve(7); ok {
		t.Fatal("duplicate occupied SessionID was reserved")
	}
	first := &Session{ID: 7}
	if !firstReservation.Publish(first) {
		t.Fatal("first reservation did not publish")
	}
	if got, ok := registry.Get(7); !ok || got != first {
		t.Fatal("published session is not visible")
	}
	if err := first.Close(false); err != nil {
		t.Fatal(err)
	}

	secondReservation, ok := registry.Reserve(7)
	if !ok {
		t.Fatal("released SessionID was not reusable")
	}
	firstReservation.Abort()
	second := &Session{ID: 7}
	if !secondReservation.Publish(second) {
		t.Fatal("stale abort removed the new reservation")
	}
	if got, ok := registry.Get(7); !ok || got != second {
		t.Fatal("new session was removed by stale cleanup")
	}
	_ = second.Close(false)
}

func TestServerSessionRegistryCloseRejectsPendingPublish(t *testing.T) {
	registry := NewServerSessionRegistry()
	reservation, ok := registry.Reserve(9)
	if !ok {
		t.Fatal("reservation failed")
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if reservation.Publish(&Session{ID: 9}) {
		t.Fatal("reservation published after registry close")
	}
	if _, ok := registry.Reserve(10); ok {
		t.Fatal("registry accepted new work after close")
	}
}
