package errors

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/log"
)

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
