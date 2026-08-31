package mtproxy

import (
	"errors"
	"testing"
	"time"
)

func TestReplayCacheRejectsDuplicateExpiresAndBounds(t *testing.T) {
	cache, err := NewReplayCache(2, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	var first, second, third [16]byte
	first[0], second[0], third[0] = 1, 2, 3

	if err := cache.CheckAndAdd(first, now); err != nil {
		t.Fatalf("first CheckAndAdd() = %v", err)
	}
	if err := cache.CheckAndAdd(first, now.Add(time.Minute)); !errors.Is(err, ErrFakeTLSReplay) {
		t.Fatalf("duplicate error = %v, want ErrFakeTLSReplay", err)
	}
	if err := cache.CheckAndAdd(second, now); err != nil {
		t.Fatalf("second CheckAndAdd() = %v", err)
	}
	if err := cache.CheckAndAdd(third, now); !errors.Is(err, ErrReplayCapacity) {
		t.Fatalf("capacity error = %v, want ErrReplayCapacity", err)
	}
	if err := cache.CheckAndAdd(first, now.Add(3*time.Hour)); err != nil {
		t.Fatalf("expired CheckAndAdd() = %v", err)
	}
}
