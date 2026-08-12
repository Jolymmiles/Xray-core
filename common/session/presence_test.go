package session

import (
	"context"
	"net/netip"
	"sync"
	"testing"
)

type recordingPresenceTracker struct {
	subject PresenceSubject
}

func (t *recordingPresenceTracker) Prepare(subject PresenceSubject) PresenceReservation {
	t.subject = subject
	return testPresenceReservation{}
}

type testPresenceReservation struct{}

func (testPresenceReservation) Activate() PresenceLease { return testPresenceLease{} }

func (testPresenceReservation) Handoff(PresenceLease) PresenceLease            { return testPresenceLease{} }
func (testPresenceReservation) HandoffAll(old []PresenceLease) []PresenceLease { return old }
func (testPresenceReservation) Abort()                                         {}

type testPresenceLease struct{}

func (testPresenceLease) Close() {}

func TestPresenceScopeIsImmutableAndPreparesCapturedSubject(t *testing.T) {
	tracker := new(recordingPresenceTracker)
	subject := PresenceSubject{
		Email:        "alice@example.com",
		Level:        7,
		IP:           netip.MustParseAddr("192.0.2.1"),
		PrincipalKey: [32]byte{1, 2, 3},
		Reusable:     true,
	}
	scope := NewPresenceScope(subject, tracker)

	copyOfSubject := scope.Subject()
	copyOfSubject.Email = "changed@example.com"
	scope.Prepare()

	if tracker.subject != subject {
		t.Fatalf("prepared subject = %+v, want %+v", tracker.subject, subject)
	}
	if got := scope.Subject(); got != subject {
		t.Fatalf("scope subject changed through returned copy: %+v", got)
	}
}

func TestZeroPresenceScopeIsAllocationFreeNoop(t *testing.T) {
	var scope PresenceScope
	if got := scope.Subject(); got != (PresenceSubject{}) {
		t.Fatalf("zero scope subject = %+v", got)
	}
	if reservation := scope.Prepare(); reservation == nil {
		t.Fatal("zero scope returned nil reservation")
	} else if lease := reservation.Activate(); lease == nil {
		t.Fatal("zero reservation returned nil lease")
	} else {
		lease.Close()
	}

	allocations := testing.AllocsPerRun(1000, func() {
		scope.Prepare().Activate().Close()
	})
	if allocations != 0 {
		t.Fatalf("zero scope prepare/activate/close allocations = %.0f, want 0", allocations)
	}
}

func TestPresenceScopeCanonicalizesAndRejectsLocalIP(t *testing.T) {
	tracker := new(recordingPresenceTracker)
	for _, ip := range []netip.Addr{
		{},
		netip.IPv4Unspecified(),
		netip.IPv6Unspecified(),
		netip.MustParseAddr("127.0.0.1"),
		netip.IPv6Loopback(),
		netip.MustParseAddr("::ffff:127.0.0.1"),
	} {
		scope := NewPresenceScope(PresenceSubject{Email: "alice@example.com", IP: ip}, tracker)
		scope.Prepare()
		if tracker.subject != (PresenceSubject{}) {
			t.Fatalf("non-canonical IP %s reached tracker as %+v", ip, tracker.subject)
		}
	}

	mapped := PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("::ffff:192.0.2.1")}
	NewPresenceScope(mapped, tracker).Prepare()
	if got := tracker.subject.IP; got != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("mapped IPv4 reached tracker as %s", got)
	}
}

func TestPresenceModeIsExplicitAndDefaultsToContext(t *testing.T) {
	if got := PresenceModeFromContext(context.Background()); got != PresenceModeContext {
		t.Fatalf("default presence mode = %v, want Context", got)
	}

	for _, mode := range []PresenceMode{PresenceModeContext, PresenceModeExternal, PresenceModeUntracked} {
		ctx := ContextWithPresenceMode(context.Background(), mode)
		if got := PresenceModeFromContext(ctx); got != mode {
			t.Fatalf("presence mode = %v, want %v", got, mode)
		}
	}
}

func TestZeroPresenceReservationTerminalsAreConcurrentNoops(t *testing.T) {
	var scope PresenceScope
	reservation := scope.Prepare()
	lease := reservation.Activate()

	var wait sync.WaitGroup
	for range 32 {
		wait.Go(func() {
			reservation.Abort()
			reservation.Activate().Close()
			reservation.Handoff(lease).Close()
			reservation.HandoffAll(nil)
			lease.Close()
		})
	}
	wait.Wait()
}
