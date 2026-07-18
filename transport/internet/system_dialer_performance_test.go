package internet

import (
	"context"
	"testing"

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

func BenchmarkDisabledDialDestinationLog(b *testing.B) {
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		logDialDestination(ctx, destination)
	}
}

func TestDisabledDialDestinationLogAllocationBudget(t *testing.T) {
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	allocations := testing.AllocsPerRun(1000, func() {
		logDialDestination(ctx, destination)
	})
	if allocations != 0 {
		t.Fatalf("disabled dial log allocations = %.0f, want 0", allocations)
	}
}
