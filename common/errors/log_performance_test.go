package errors

import (
	"context"
	stderrors "errors"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/log"
)

var errorStringBenchmarkSink string

type severityFilteringHandler struct {
	handled atomic.Int64
}

func (h *severityFilteringHandler) Handle(log.Message) {
	h.handled.Add(1)
}

func (*severityFilteringHandler) Enabled(severity log.Severity) bool {
	return severity <= log.Severity_Error
}

func TestDisabledLogSkipsMessageConstruction(t *testing.T) {
	handler := new(severityFilteringHandler)
	log.RegisterHandler(handler)

	LogInfo(context.Background(), "disabled info")
	if handled := handler.handled.Load(); handled != 0 {
		t.Fatalf("disabled handler received %d messages, want 0", handled)
	}
}

func TestDisabledLogAllocationBudget(t *testing.T) {
	handler := new(severityFilteringHandler)
	log.RegisterHandler(handler)
	allocations := testing.AllocsPerRun(1000, func() {
		LogInfo(context.Background(), "disabled info")
	})
	if allocations != 0 {
		t.Fatalf("disabled LogInfo allocations = %.0f, want 0", allocations)
	}
}

func TestEnabledLogStillReachesHandler(t *testing.T) {
	handler := new(severityFilteringHandler)
	log.RegisterHandler(handler)

	LogError(context.Background(), "enabled error")
	if handled := handler.handled.Load(); handled != 1 {
		t.Fatalf("enabled handler received %d messages, want 1", handled)
	}
}

func TestInnerErrorSeverityKeepsPromotedLogEnabled(t *testing.T) {
	handler := new(severityFilteringHandler)
	log.RegisterHandler(handler)

	LogInfoInner(context.Background(), New("inner").AtError(), "promoted error")
	if handled := handler.handled.Load(); handled != 1 {
		t.Fatalf("promoted handler received %d messages, want 1", handled)
	}
}

func BenchmarkDisabledLogInfo(b *testing.B) {
	handler := new(severityFilteringHandler)
	log.RegisterHandler(handler)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		LogInfo(ctx, "disabled info")
	}
}

func BenchmarkDisabledLogInfoParallel(b *testing.B) {
	handler := new(severityFilteringHandler)
	log.RegisterHandler(handler)
	ctx := context.Background()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			LogInfo(ctx, "disabled info")
		}
	})
}

func BenchmarkEnabledLogError(b *testing.B) {
	handler := new(severityFilteringHandler)
	log.RegisterHandler(handler)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		LogError(ctx, "enabled error")
	}
}

func BenchmarkErrorString(b *testing.B) {
	err := New("failed to dispatch ", "example.com:443").Base(stderrors.New("upstream unavailable")).AtWarning()
	b.ReportAllocs()
	for b.Loop() {
		errorStringBenchmarkSink = err.Error()
	}
}
