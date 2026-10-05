package mtproxy

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func replayKey(value uint64) [16]byte {
	var key [16]byte
	binary.LittleEndian.PutUint64(key[:8], value)
	binary.LittleEndian.PutUint64(key[8:], value^0x9e3779b97f4a7c15)
	return key
}

func TestBloomReplayCacheDetectsAndRotates(t *testing.T) {
	cache, err := NewBloomReplayCache(1024, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	key := replayKey(1)
	if err := cache.CheckAndAdd(key, now); err != nil {
		t.Fatal(err)
	}
	if err := cache.CheckAndAdd(key, now.Add(9*time.Minute)); err != ErrFakeTLSReplay {
		t.Fatalf("current-window replay error = %v", err)
	}
	if err := cache.CheckAndAdd(key, now.Add(11*time.Minute)); err != ErrFakeTLSReplay {
		t.Fatalf("previous-window replay error = %v", err)
	}
	if err := cache.CheckAndAdd(key, now.Add(21*time.Minute)); err != nil {
		t.Fatalf("expired replay key was not admitted: %v", err)
	}
}

func TestBloomReplayCacheMemoryIsCapacityBounded(t *testing.T) {
	const capacity = 65536
	cache, err := NewBloomReplayCache(capacity, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	maximum := 2 * ((capacity*15 + 63) / 64) * 8
	if got := cache.MemoryBytes(); got > maximum {
		t.Fatalf("MemoryBytes() = %d, want <= %d", got, maximum)
	}
	for i := 0; i < capacity*2; i++ {
		_ = cache.CheckAndAdd(replayKey(uint64(i)), time.Unix(1_700_000_000, 0))
	}
	if got := cache.MemoryBytes(); got > maximum {
		t.Fatalf("memory grew after inserts: %d > %d", got, maximum)
	}
}

func TestBloomReplayCacheConcurrentAccess(t *testing.T) {
	cache, _ := NewBloomReplayCache(4096, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < 1000; i++ {
				_ = cache.CheckAndAdd(replayKey(uint64(worker*1000+i)), now)
			}
		}()
	}
	wait.Wait()
}

func TestBloomReplayCacheRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewBloomReplayCache(0, time.Minute); err == nil {
		t.Fatal("zero capacity accepted")
	}
	if _, err := NewBloomReplayCache(1, 0); err == nil {
		t.Fatal("zero rotation interval accepted")
	}
}
