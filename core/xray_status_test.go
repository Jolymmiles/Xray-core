package core_test

import (
	"sync"
	"testing"

	. "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// closeConcurrently starts a started instance's Close together with op and
// waits for both. Run with -race: op must synchronize with Close.
func closeConcurrently(t *testing.T, instance *Instance, op func()) {
	t.Helper()
	start := make(chan struct{})
	closed := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		closed <- instance.Close()
	}()
	go func() {
		defer wg.Done()
		<-start
		op()
	}()
	close(start)
	wg.Wait()
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

// Transports such as Hysteria poll IsRunning from their own goroutines to
// release the connections of a stopped instance.
func TestInstanceIsRunningSynchronizesWithClose(t *testing.T) {
	instance := new(Instance)
	if instance.IsRunning() {
		t.Fatal("a new instance reports running")
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	if !instance.IsRunning() {
		t.Fatal("a started instance reports not running")
	}

	closeConcurrently(t, instance, func() { _ = instance.IsRunning() })

	if instance.IsRunning() {
		t.Fatal("instance reports running after Close")
	}
}

func TestInstanceAddFeatureSynchronizesWithClose(t *testing.T) {
	instance := new(Instance)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}

	var added error
	closeConcurrently(t, instance, func() { added = instance.AddFeature(localdns.New()) })

	if added != nil {
		t.Fatal(added)
	}
}
