package mtproxy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSecretDeleteHardRevokesOnlyAssociatedSessions(t *testing.T) {
	registry, err := NewSecretRegistry(4)
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint, _, _ := registry.Add(testSecret(10))
	secondFingerprint, _, _ := registry.Add(testSecret(20))

	var firstClosed atomic.Int32
	var secondClosed atomic.Int32
	unregisterFirst, ok := registry.RegisterSession(firstFingerprint, 1, func() {
		firstClosed.Add(1)
		_ = registry.Len() // callback must run outside registry locks
	})
	if !ok {
		t.Fatal("RegisterSession(first) failed")
	}
	defer unregisterFirst()
	unregisterSecond, ok := registry.RegisterSession(secondFingerprint, 2, func() { secondClosed.Add(1) })
	if !ok {
		t.Fatal("RegisterSession(second) failed")
	}
	defer unregisterSecond()

	if !registry.Delete(firstFingerprint) {
		t.Fatal("Delete(first) failed")
	}
	if got := firstClosed.Load(); got != 1 {
		t.Fatalf("first close count = %d, want 1", got)
	}
	if got := secondClosed.Load(); got != 0 {
		t.Fatalf("second close count = %d, want 0", got)
	}
	if registry.Delete(firstFingerprint) {
		t.Fatal("second Delete(first) succeeded")
	}
	if got := firstClosed.Load(); got != 1 {
		t.Fatalf("first close count after second delete = %d, want 1", got)
	}
}

func TestSecretDeleteRejectsOldSnapshotRegistration(t *testing.T) {
	registry, err := NewSecretRegistry(1)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _, _ := registry.Add(testSecret(30))
	snapshot := registry.candidates()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot length = %d", len(snapshot))
	}

	if !registry.Delete(fingerprint) {
		t.Fatal("Delete() failed")
	}
	if unregister, ok := snapshot[0].runtime.register(99, func() {}); ok || unregister != nil {
		t.Fatal("revoked runtime accepted old-snapshot registration")
	}
	if unregister, ok := registry.RegisterSession(fingerprint, 100, func() {}); ok || unregister != nil {
		t.Fatal("registry accepted removed fingerprint")
	}
}

func TestSecretDeleteAndUnregisterRaceClosesAtMostOnce(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		registry, _ := NewSecretRegistry(1)
		fingerprint, _, _ := registry.Add(testSecret(byte(iteration)))
		var closed atomic.Int32
		unregister, ok := registry.RegisterSession(fingerprint, 1, func() { closed.Add(1) })
		if !ok {
			t.Fatal("RegisterSession() failed")
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			unregister()
		}()
		go func() {
			defer wg.Done()
			<-start
			registry.Delete(fingerprint)
		}()
		close(start)
		wg.Wait()
		if got := closed.Load(); got > 1 {
			t.Fatalf("close count = %d, want at most 1", got)
		}
	}
}

func TestSecretDeleteDoesNotBlockOnRegistryLockDuringClose(t *testing.T) {
	registry, _ := NewSecretRegistry(1)
	fingerprint, _, _ := registry.Add(testSecret(40))
	callbackDone := make(chan struct{})
	_, ok := registry.RegisterSession(fingerprint, 1, func() {
		registry.List()
		close(callbackDone)
	})
	if !ok {
		t.Fatal("RegisterSession() failed")
	}

	deleted := make(chan struct{})
	go func() {
		registry.Delete(fingerprint)
		close(deleted)
	}()

	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("close callback blocked on registry lock")
	}
	select {
	case <-deleted:
	case <-time.After(time.Second):
		t.Fatal("Delete() did not return")
	}
}
