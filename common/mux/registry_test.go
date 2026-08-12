package mux

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/session"
)

func TestClientSessionManagerWrapsAndSkipsOccupiedIDs(t *testing.T) {
	manager := newClientSessionManager()
	first := manager.allocate(&ClientStrategy{})
	if first == nil || first.id != 1 {
		t.Fatalf("first allocation = %+v, want ID 1", first)
	}
	manager.nextID = ^uint16(0) - 1
	last := manager.allocate(&ClientStrategy{})
	if last == nil || last.id != ^uint16(0) {
		t.Fatalf("last allocation = %+v, want ID 65535", last)
	}
	wrapped := manager.allocate(&ClientStrategy{})
	if wrapped == nil || wrapped.id != 2 {
		t.Fatalf("wrapped allocation = %+v, want occupied ID 1 skipped to 2", wrapped)
	}
}

func TestClientSessionManagerHonorsAdmissionAndLifetimeLimits(t *testing.T) {
	manager := newClientSessionManager()
	concurrency := &ClientStrategy{MaxConcurrency: 1}
	if manager.allocate(concurrency) == nil {
		t.Fatal("first concurrent allocation failed")
	}
	if manager.allocate(concurrency) != nil {
		t.Fatal("pending slot did not consume concurrency")
	}

	limited := newClientSessionManager()
	strategy := &ClientStrategy{MaxConnection: 1}
	admission := limited.allocate(strategy)
	admission.abort()
	if limited.allocate(strategy) != nil {
		t.Fatal("lifetime limit was reset after slot close")
	}
}

func TestClientSessionManagerRejectsExhaustedIDSpace(t *testing.T) {
	manager := newClientSessionManager()
	for id := uint32(1); id <= uint32(^uint16(0)); id++ {
		manager.registry.slots[uint16(id)] = &sessionSlot{token: uint64(id)}
	}
	if manager.allocate(&ClientStrategy{}) != nil {
		t.Fatal("allocation overwrote an occupied 16-bit ID")
	}
}

func TestServerSessionRegistryRejectsDuplicateAndStaleToken(t *testing.T) {
	registry := newServerSessionRegistry()
	first := registry.reserve(7)
	if first == nil {
		t.Fatal("first reservation failed")
	}
	if registry.reserve(7) != nil {
		t.Fatal("duplicate peer ID was reserved")
	}
	first.abort()
	second := registry.reserve(7)
	if second == nil || second.token == first.token {
		t.Fatalf("reused reservation token = %d, first = %d", second.token, first.token)
	}
	first.abort()
	if registry.admitted() != 1 {
		t.Fatal("stale abort removed the reused peer ID")
	}
}

func TestSessionAdmissionPublishesResourcesAndLeaseTogether(t *testing.T) {
	registry := newServerSessionRegistry()
	admission := registry.reserve(9)
	if _, found := registry.active(9); found {
		t.Fatal("reserved slot was visible as active")
	}
	if !admission.beginCommit() {
		t.Fatal("begin commit failed")
	}
	if _, found := registry.active(9); found {
		t.Fatal("activating slot was visible as active")
	}
	lease := new(countingRegistryLease)
	owner := new(Session)
	if !admission.finishCommit(owner, lease) {
		t.Fatal("finish commit failed")
	}
	if got, found := registry.active(9); !found || got != owner {
		t.Fatalf("active slot = %p, %v; want %p, true", got, found, owner)
	}
	if owner.ownerToken != admission.token {
		t.Fatalf("published owner token = %d, want %d", owner.ownerToken, admission.token)
	}
	if lease.closed.Load() != 0 {
		t.Fatal("published lease was closed")
	}
	owner.Close(false)
	if _, found := registry.active(9); found {
		t.Fatal("closed owner remained active")
	}
	if lease.closed.Load() != 1 {
		t.Fatalf("lease close count = %d, want 1", lease.closed.Load())
	}
	owner.Close(false)
	if lease.closed.Load() != 1 {
		t.Fatalf("duplicate owner close count = %d, want 1", lease.closed.Load())
	}
}

func TestSessionAdmissionShutdownRejectsLateCommit(t *testing.T) {
	registry := newServerSessionRegistry()
	admission := registry.reserve(11)
	if !admission.beginCommit() {
		t.Fatal("begin commit failed")
	}
	closed := make(chan struct{})
	go func() {
		registry.close()
		close(closed)
	}()
	for !registry.isClosing() {
		runtime.Gosched()
	}
	if admission.finishCommit(new(Session), new(countingRegistryLease)) {
		t.Fatal("late commit published during shutdown")
	}
	<-closed
	if registry.admitted() != 0 {
		t.Fatal("shutdown left admitted slots")
	}
}

func TestSessionRegistryShutdownCancelsPendingPreparation(t *testing.T) {
	registry := newServerSessionRegistry()
	admission := registry.reserve(12)
	ctx, cancel := context.WithCancel(context.Background())
	if !admission.prepare(cancel) {
		t.Fatal("prepare failed")
	}
	registry.close()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("shutdown did not cancel pending preparation")
	}
	if admission.beginCommit() {
		t.Fatal("pending preparation committed after shutdown")
	}
}

func TestSessionRegistryClosesLeaseOutsideLock(t *testing.T) {
	registry := newServerSessionRegistry()
	admission := registry.reserve(13)
	if !admission.beginCommit() {
		t.Fatal("begin commit failed")
	}
	reentered := make(chan int, 1)
	lease := &callbackRegistryLease{close: func() { reentered <- registry.admitted() }}
	owner := new(Session)
	if !admission.finishCommit(owner, lease) {
		t.Fatal("finish commit failed")
	}
	owner.Close(false)
	select {
	case got := <-reentered:
		if got != 0 {
			t.Fatalf("admitted during lease close = %d, want 0", got)
		}
	case <-time.After(time.Second):
		t.Fatal("lease close could not re-enter registry")
	}
}

func TestSessionOwnerConvergesConcurrentTerminalPaths(t *testing.T) {
	registry := newServerSessionRegistry()
	admission := registry.reserve(14)
	if !admission.beginCommit() {
		t.Fatal("begin commit failed")
	}
	lease := new(countingRegistryLease)
	owner := new(Session)
	if !admission.finishCommit(owner, lease) {
		t.Fatal("finish commit failed")
	}
	var callers sync.WaitGroup
	for range 100 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			_ = owner.Close(false)
		}()
	}
	callers.Wait()
	if registry.admitted() != 0 || lease.closed.Load() != 1 {
		t.Fatalf("terminal race left admitted=%d lease closes=%d", registry.admitted(), lease.closed.Load())
	}
}

type countingRegistryLease struct {
	once   sync.Once
	closed atomic.Int32
}

func (l *countingRegistryLease) Close() {
	l.once.Do(func() { l.closed.Add(1) })
}

var _ session.PresenceLease = (*countingRegistryLease)(nil)

type callbackRegistryLease struct {
	once  sync.Once
	close func()
}

func (l *callbackRegistryLease) Close() { l.once.Do(l.close) }
