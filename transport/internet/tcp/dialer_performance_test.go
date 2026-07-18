package tcp

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
)

type warningDiscardLogHandler struct{}

func (warningDiscardLogHandler) Handle(log.Message) {}
func (warningDiscardLogHandler) Enabled(severity log.Severity) bool {
	return severity <= log.Severity_Warning
}

func init() {
	log.RegisterHandler(warningDiscardLogHandler{})
}

func BenchmarkDisabledTCPDialLog(b *testing.B) {
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		logTCPDialDestination(ctx, destination)
	}
}

func BenchmarkDisabledTCPDialLogLegacy(b *testing.B) {
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		errors.LogInfo(ctx, "dialing TCP to ", destination)
	}
}

func TestDisabledTCPDialLogAllocationBudget(t *testing.T) {
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	allocations := testing.AllocsPerRun(1000, func() {
		logTCPDialDestination(ctx, destination)
	})
	if allocations != 0 {
		t.Fatalf("disabled TCP dial log allocations = %.0f, want 0", allocations)
	}
}
