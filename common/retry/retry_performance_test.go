package retry

import (
	"errors"
	"testing"
)

func BenchmarkExponentialBackoffFirstAttemptSuccess(b *testing.B) {
	success := func() error { return nil }
	b.ReportAllocs()
	for b.Loop() {
		if err := ExponentialBackoff(5, 100).On(success); err != nil {
			b.Fatal(err)
		}
	}
}

func TestExponentialBackoffFirstAttemptSuccessAllocationBudget(t *testing.T) {
	success := func() error { return nil }
	allocations := testing.AllocsPerRun(1000, func() {
		if err := ExponentialBackoff(5, 100).On(success); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("first-attempt retry allocations = %.0f, want 0", allocations)
	}
}

func BenchmarkExponentialBackoffSecondAttemptSuccess(b *testing.B) {
	firstFailure := errors.New("first attempt failed")
	b.ReportAllocs()
	for b.Loop() {
		attempt := 0
		if err := ExponentialBackoff(5, 100).On(func() error {
			attempt++
			if attempt == 1 {
				return firstFailure
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestExponentialBackoffSecondAttemptSuccessAllocationBudget(t *testing.T) {
	firstFailure := errors.New("first attempt failed")
	allocations := testing.AllocsPerRun(1000, func() {
		attempt := 0
		if err := ExponentialBackoff(5, 100).On(func() error {
			attempt++
			if attempt == 1 {
				return firstFailure
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("second-attempt retry allocations = %.0f, want 0", allocations)
	}
}

func BenchmarkExponentialBackoffRepeatedFailure(b *testing.B) {
	repeatedFailure := errors.New("repeated failure")
	b.ReportAllocs()
	for b.Loop() {
		if err := ExponentialBackoff(5, 0).On(func() error {
			return repeatedFailure
		}); err == nil {
			b.Fatal("retry unexpectedly succeeded")
		}
	}
}
