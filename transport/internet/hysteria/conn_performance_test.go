package hysteria

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var interConnTimeBenchmarkSink time.Time
var udpSessionMapBenchmarkSink map[uint32]*InterConn
var interConnBenchmarkSink *InterConn
var legacyCloseBenchmarkSink func()
var legacyWriteBenchmarkSink func([]byte) error
var managerClosedBenchmarkSink bool

func activeSessionManager(count int) *udpSessionManager {
	manager := &udpSessionManager{m: make(map[uint32]*InterConn, count), udpIdleTimeout: time.Minute}
	for index := range count {
		connection := &InterConn{id: uint32(index), ch: make(chan []byte, 1)}
		connection.Update()
		manager.m[connection.id] = connection
	}
	return manager
}

func TestInterConnActivityTimestamp(t *testing.T) {
	connection := new(InterConn)
	before := time.Now()
	connection.Update()
	after := time.Now()
	activity := connection.Time()
	if activity.Before(before) || activity.After(after) {
		t.Fatalf("activity timestamp %v outside [%v, %v]", activity, before, after)
	}
}

func TestInterConnUsesManagerClock(t *testing.T) {
	var clock atomic.Int64
	now := time.Now().UnixNano()
	clock.Store(now)
	connection := &InterConn{clock: &clock}
	connection.Update()
	if got := connection.active.Load(); got != now {
		t.Fatalf("activity = %d, want manager clock %d", got, now)
	}
}

func TestInterConnConcurrentWriteAndClose(t *testing.T) {
	connection := &InterConn{
		id: 1,
		ch: make(chan []byte, 1),
	}
	manager := &udpSessionManager{m: map[uint32]*InterConn{1: connection}, send: func([]byte) error { return nil }}
	connection.manager = manager
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		for range 1000 {
			_, _ = connection.Write(make([]byte, 4))
		}
	}()
	go func() {
		defer wait.Done()
		<-start
		manager.Lock()
		manager.close(connection)
		manager.Unlock()
	}()
	close(start)
	wait.Wait()
}

func TestUDPSessionManagerCleanupConcurrentClose(t *testing.T) {
	manager := new(udpSessionManager)
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		for range 100000 {
			_ = manager.isClosed()
		}
	}()
	go func() {
		defer wait.Done()
		<-start
		for index := range 100000 {
			manager.closed.Store(index%2 == 0)
		}
	}()
	close(start)
	wait.Wait()
}

func TestUDPSessionManagerCleanInactive(t *testing.T) {
	now := time.Now()
	manager := &udpSessionManager{m: make(map[uint32]*InterConn), udpIdleTimeout: time.Minute}
	stale := &InterConn{id: 1, ch: make(chan []byte, 1)}
	stale.active.Store(now.Add(-2 * time.Minute).UnixNano())
	active := &InterConn{id: 2, ch: make(chan []byte, 1)}
	active.active.Store(now.UnixNano())
	manager.m[stale.id] = stale
	manager.m[active.id] = active

	manager.cleanInactive(now)
	if _, found := manager.m[stale.id]; found || !stale.closed.Load() {
		t.Fatal("stale UDP session was not closed and removed")
	}
	if _, found := manager.m[active.id]; !found || active.closed.Load() {
		t.Fatal("active UDP session was closed")
	}
}

func TestUDPSessionManagerCleanInactiveTimeoutBoundary(t *testing.T) {
	now := time.Now()
	manager := &udpSessionManager{m: make(map[uint32]*InterConn), udpIdleTimeout: time.Minute}
	atBoundary := &InterConn{id: 1, ch: make(chan []byte, 1)}
	atBoundary.active.Store(now.Add(-time.Minute).UnixNano())
	overBoundary := &InterConn{id: 2, ch: make(chan []byte, 1)}
	overBoundary.active.Store(now.Add(-time.Minute - time.Nanosecond).UnixNano())
	manager.m[atBoundary.id] = atBoundary
	manager.m[overBoundary.id] = overBoundary

	manager.cleanInactive(now)
	if atBoundary.closed.Load() {
		t.Fatal("session exactly at timeout boundary was closed")
	}
	if !overBoundary.closed.Load() {
		t.Fatal("session beyond timeout boundary remained open")
	}
}

func TestUDPSessionManagerCleanAllocationBudget(t *testing.T) {
	manager := activeSessionManager(64)
	now := time.Now()
	allocations := testing.AllocsPerRun(1000, func() {
		manager.cleanInactive(now)
	})
	if allocations != 0 {
		t.Fatalf("active UDP cleanup allocations = %.0f, want 0", allocations)
	}
}

func BenchmarkInterConnUpdate(b *testing.B) {
	connection := new(InterConn)
	b.ReportAllocs()
	for b.Loop() {
		connection.Update()
	}
}

func BenchmarkInterConnUpdateCoarseClock(b *testing.B) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	connection := &InterConn{clock: &clock}
	b.ReportAllocs()
	for b.Loop() {
		connection.Update()
	}
}

func BenchmarkInterConnUpdateParallel(b *testing.B) {
	connection := new(InterConn)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			connection.Update()
		}
	})
}

func BenchmarkInterConnTime(b *testing.B) {
	connection := new(InterConn)
	connection.Update()
	b.ReportAllocs()
	for b.Loop() {
		interConnTimeBenchmarkSink = connection.Time()
	}
}

func BenchmarkUDPSessionManagerCleanActive64(b *testing.B) {
	manager := activeSessionManager(64)
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		manager.cleanInactive(now)
	}
}

func BenchmarkUDPSessionManagerFeedExisting(b *testing.B) {
	connection := &InterConn{id: 1, ch: make(chan []byte, 1)}
	manager := &udpSessionManager{m: map[uint32]*InterConn{1: connection}}
	payload := []byte{0, 0, 0, 1, 1, 2, 3, 4}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		manager.feed(1, payload)
		<-connection.ch
	}
}

func BenchmarkUDPSessionMapInitialCapacity(b *testing.B) {
	connections := make([]*InterConn, initialUDPSessionCapacity)
	for index := range connections {
		connections[index] = &InterConn{id: uint32(index)}
	}
	b.Run("zero-capacity", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sessions := make(map[uint32]*InterConn)
			for index, connection := range connections {
				sessions[uint32(index)] = connection
			}
			udpSessionMapBenchmarkSink = sessions
		}
	})
	b.Run("preallocated", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sessions := newUDPSessionMap()
			for index, connection := range connections {
				sessions[uint32(index)] = connection
			}
			udpSessionMapBenchmarkSink = sessions
		}
	})
}

func BenchmarkInterConnOwnershipSetup(b *testing.B) {
	manager := new(udpSessionManager)
	b.Run("per-session-closures", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			connection := &InterConn{ch: make(chan []byte, 1)}
			legacyWrite := func([]byte) error { return nil }
			legacyClose := func() { manager.close(connection) }
			legacyWriteBenchmarkSink = legacyWrite
			legacyCloseBenchmarkSink = legacyClose
			interConnBenchmarkSink = connection
		}
	})
	b.Run("manager-owned", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			interConnBenchmarkSink = &InterConn{ch: make(chan []byte, 1), manager: manager}
		}
	})
}

func BenchmarkInterConnRepeatedClose(b *testing.B) {
	connection := &InterConn{id: 1, ch: make(chan []byte, 1)}
	manager := &udpSessionManager{m: map[uint32]*InterConn{1: connection}}
	connection.manager = manager
	if err := connection.Close(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := connection.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPSessionManagerIsClosed(b *testing.B) {
	manager := new(udpSessionManager)
	b.ReportAllocs()
	for b.Loop() {
		managerClosedBenchmarkSink = manager.isClosed()
	}
}
