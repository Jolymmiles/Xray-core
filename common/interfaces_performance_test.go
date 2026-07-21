package common_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
)

type benchmarkInterruptible struct{}

func (*benchmarkInterruptible) Interrupt() {}

type benchmarkClosable struct{}

func (*benchmarkClosable) Close() error { return nil }

// BenchmarkInterrupt measures common.Interrupt (teardown path, not data plane).
func BenchmarkInterrupt(b *testing.B) {
	interruptible := new(benchmarkInterruptible)
	closable := new(benchmarkClosable)

	b.Run("interruptible", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = common.Interrupt(interruptible)
		}
	})
	b.Run("closable", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = common.Interrupt(closable)
		}
	})
	b.Run("nil", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = common.Interrupt(nil)
		}
	})
}

func TestInterruptNonNilAllocationBudget(t *testing.T) {
	obj := new(benchmarkInterruptible)
	allocations := testing.AllocsPerRun(1000, func() {
		_ = common.Interrupt(obj)
	})
	if allocations != 0 {
		t.Fatalf("Interrupt allocations = %.0f, want zero", allocations)
	}
}
