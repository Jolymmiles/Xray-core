package log_test

import (
	"context"
	"io"
	"testing"
	"time"

	corelog "github.com/xtls/xray-core/common/log"
)

func TestRuntimeEmitAllocationBudget(t *testing.T) {
	output := newGatedOutput()
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Outputs: []corelog.OutputOptions{{
			Name:          "allocation",
			Output:        output,
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     2048,
			BatchSize:     1,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureDropNew,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 16, 2, 0, 0, time.UTC),
		Severity:  corelog.Severity_Info,
	}, "event")
	runtime.Emit(event)
	select {
	case <-output.writeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not enter the gated output")
	}

	allocations := testing.AllocsPerRun(1000, func() { runtime.Emit(event) })
	if allocations != 0 {
		t.Fatalf("Runtime.Emit allocations = %.0f, want 0", allocations)
	}

	close(output.releaseWrite)
	closeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeBlockFastPathAllocationBudget(t *testing.T) {
	output := newGatedOutput()
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Emergency: io.Discard,
		Outputs: []corelog.OutputOptions{{
			Name:          "block-allocation",
			Output:        output,
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     2048,
			BatchSize:     1,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureBlock,
			BlockTimeout:  time.Second,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 16, 2, 0, 0, time.UTC),
		Severity:  corelog.Severity_Info,
	}, "event")
	runtime.Emit(event)
	select {
	case <-output.writeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not enter the gated output")
	}

	allocations := testing.AllocsPerRun(1000, func() { runtime.Emit(event) })
	if allocations != 0 {
		t.Fatalf("block fast-path Runtime.Emit allocations = %.0f, want 0", allocations)
	}

	close(output.releaseWrite)
	closeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeSyncAllocationBudget(t *testing.T) {
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{Outputs: []corelog.OutputOptions{{
		Name:          "sync-allocation",
		Output:        corelog.NewConsoleOutput(io.Discard),
		Encoder:       corelog.JSONEncoder{},
		Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
		MaxSeverity:   corelog.Severity_Info,
		QueueSize:     1,
		BatchSize:     1,
		FlushInterval: time.Hour,
		Backpressure:  corelog.BackpressureSync,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 16, 2, 0, 0, time.UTC),
		Severity:  corelog.Severity_Info,
	}, "event")
	allocations := testing.AllocsPerRun(1000, func() { runtime.Emit(event) })
	if allocations != 0 {
		t.Fatalf("sync Runtime.Emit allocations = %.0f, want 0", allocations)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

var runtimeBenchmarkStats []corelog.OutputStats

func BenchmarkRuntimeEmit(b *testing.B) {
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Outputs: []corelog.OutputOptions{{
			Name:          "discard",
			Output:        corelog.NewConsoleOutput(io.Discard),
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     1024,
			BatchSize:     32,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureDropNew,
		}},
	})
	if err != nil {
		b.Fatal(err)
	}
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 16, 2, 0, 0, time.UTC),
		Severity:  corelog.Severity_Info,
	}, "event")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runtime.Emit(event)
	}
	b.StopTimer()
	if err := runtime.Close(context.Background()); err != nil {
		b.Fatal(err)
	}
	runtimeBenchmarkStats = runtime.Stats()
}

func BenchmarkRuntimeEmitParallel(b *testing.B) {
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Outputs: []corelog.OutputOptions{{
			Name:          "discard",
			Output:        corelog.NewConsoleOutput(io.Discard),
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     1024,
			BatchSize:     32,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureDropNew,
		}},
	})
	if err != nil {
		b.Fatal(err)
	}
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 16, 2, 0, 0, time.UTC),
		Severity:  corelog.Severity_Info,
	}, "event")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			runtime.Emit(event)
		}
	})
	b.StopTimer()
	if err := runtime.Close(context.Background()); err != nil {
		b.Fatal(err)
	}
	runtimeBenchmarkStats = runtime.Stats()
}

func BenchmarkRuntimeEmitSync(b *testing.B) {
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{Outputs: []corelog.OutputOptions{{
		Name: "sync", Output: corelog.NewConsoleOutput(io.Discard), Encoder: corelog.JSONEncoder{},
		Kinds: corelog.KindMaskOf(corelog.KindGeneral), MaxSeverity: corelog.Severity_Info,
		QueueSize: 1, BatchSize: 1, FlushInterval: time.Hour, Backpressure: corelog.BackpressureSync,
	}}})
	if err != nil {
		b.Fatal(err)
	}
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 16, 2, 0, 0, time.UTC),
		Severity:  corelog.Severity_Info,
	}, "event")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runtime.Emit(event)
	}
	b.StopTimer()
	if err := runtime.Close(context.Background()); err != nil {
		b.Fatal(err)
	}
}
