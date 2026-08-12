package mux

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestRuntimeXUDPKeyUsesAuthenticatedReusablePrincipal(t *testing.T) {
	runtime := newRuntime()
	defer runtime.Close()
	globalID := [8]byte{1, 2, 3}
	principal := [32]byte{9, 8, 7}
	scope := session.NewPresenceScope(session.PresenceSubject{
		Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.1"), PrincipalKey: principal, Reusable: true,
	}, runtimeTestTracker{})
	left := runtime.xudpKey(scope, 11, globalID)
	right := runtime.xudpKey(scope, 22, globalID)
	if left != right || left.principal != principal || left.worker != 0 {
		t.Fatalf("reusable keys = %+v, %+v", left, right)
	}

	otherScope := session.NewPresenceScope(session.PresenceSubject{
		Email: "bob@example.com", IP: netip.MustParseAddr("192.0.2.1"), PrincipalKey: [32]byte{6}, Reusable: true,
	}, runtimeTestTracker{})
	if runtime.xudpKey(otherScope, 11, globalID) == left {
		t.Fatal("different principals shared an XUDP key")
	}
}

func TestRuntimeXUDPKeyIsolatesNonReusableWorkersAndRuntimes(t *testing.T) {
	first := newRuntime()
	defer first.Close()
	second := newRuntime()
	defer second.Close()
	globalID := [8]byte{4, 5, 6}
	scope := session.NewPresenceScope(session.PresenceSubject{
		Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.1"), Reusable: false,
	}, runtimeTestTracker{})
	if first.xudpKey(scope, 1, globalID) == first.xudpKey(scope, 2, globalID) {
		t.Fatal("non-reusable workers shared an XUDP key")
	}
	if first.id == second.id {
		t.Fatal("runtime identities collided")
	}
}

func TestRuntimeFreezesCompleteXUDPDestination(t *testing.T) {
	target := freezeXUDPDestination(X.UDPDestination(X.DomainAddress("example.com"), 53))
	for name, candidate := range map[string]X.Destination{
		"network": X.TCPDestination(X.DomainAddress("example.com"), 53),
		"address": X.UDPDestination(X.DomainAddress("other.example"), 53),
		"port":    X.UDPDestination(X.DomainAddress("example.com"), 5353),
	} {
		if target.matches(candidate) {
			t.Fatalf("%s mismatch accepted", name)
		}
	}
	if !target.matches(X.UDPDestination(X.DomainAddress("example.com"), 53)) {
		t.Fatal("equal destination rejected")
	}
}

func TestRuntimeCloseUnblocksRegisteredResponseSink(t *testing.T) {
	runtime := newRuntime()
	writer := &blockingRuntimeWriter{started: make(chan struct{}), closed: make(chan struct{})}
	sink := runtime.newResponseSink(writer)
	if !sink.enqueue(1, buf.MultiBuffer{buf.FromBytes([]byte("blocked"))}) {
		t.Fatal("response enqueue failed")
	}
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("response sink did not block in writer")
	}
	done := make(chan struct{})
	go func() {
		_ = runtime.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runtime close did not unblock response sink")
	}
}

func TestRuntimeCloseWaitsForAuthorizedTransaction(t *testing.T) {
	runtime := newRuntime()
	_, finish, ok := runtime.beginTransaction(context.Background())
	if !ok {
		t.Fatal("transaction admission failed")
	}
	done := make(chan struct{})
	go func() {
		_ = runtime.Close()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("runtime closed before transaction cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	finish()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runtime did not close after transaction cleanup")
	}
}

type blockingRuntimeWriter struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (w *blockingRuntimeWriter) WriteMultiBuffer(payload buf.MultiBuffer) error {
	close(w.started)
	<-w.closed
	buf.ReleaseMulti(payload)
	return io.ErrClosedPipe
}

func (w *blockingRuntimeWriter) Close() error {
	w.once.Do(func() { close(w.closed) })
	return nil
}

type runtimeTestTracker struct{}

func (runtimeTestTracker) Prepare(session.PresenceSubject) session.PresenceReservation {
	return noopPresenceReservation{}
}

type noopPresenceReservation struct{}

func (noopPresenceReservation) Activate() session.PresenceLease { return noopPresenceLease{} }
func (noopPresenceReservation) Handoff(old session.PresenceLease) session.PresenceLease {
	if old != nil {
		old.Close()
	}
	return noopPresenceLease{}
}

func (noopPresenceReservation) HandoffAll([]session.PresenceLease) []session.PresenceLease {
	return nil
}
func (noopPresenceReservation) Abort() {}

type noopPresenceLease struct{}

func (noopPresenceLease) Close() {}
