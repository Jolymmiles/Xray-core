package freedom

import (
	"context"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
)

var finalRuleBenchmarkSink bool

type warningDiscardLogHandler struct{}

func (warningDiscardLogHandler) Handle(log.Message) {}
func (warningDiscardLogHandler) Enabled(severity log.Severity) bool {
	return severity <= log.Severity_Warning
}

func init() {
	log.RegisterHandler(warningDiscardLogHandler{})
}

func BenchmarkFinalRuleDirectIPv4(b *testing.B) {
	rules, err := geodata.ParseIPRules([]string{"192.0.2.0/24"})
	if err != nil {
		b.Fatal(err)
	}
	matcher, err := geodata.IPReg.BuildIPMatcher(rules)
	if err != nil {
		b.Fatal(err)
	}
	rule := &FinalRule{network: allNetworks, ip: matcher}
	address := net.IPv4Address([4]byte{192, 0, 2, 1})

	b.ReportAllocs()
	for b.Loop() {
		finalRuleBenchmarkSink = rule.Apply(net.Network_TCP, address, 443)
	}
}

func BenchmarkDisabledFreedomDialLog(b *testing.B) {
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		logFreedomDialDestination(ctx, destination)
	}
}

func TestDisabledFreedomDialLogAllocationBudget(t *testing.T) {
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	allocations := testing.AllocsPerRun(1000, func() {
		logFreedomDialDestination(ctx, destination)
	})
	if allocations != 0 {
		t.Fatalf("disabled Freedom dial log allocations = %.0f, want 0", allocations)
	}
}

func BenchmarkDisabledFreedomConnectionOpenedLog(b *testing.B) {
	client, server := stdnet.Pipe()
	b.Cleanup(func() {
		client.Close()
		server.Close()
	})
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		logFreedomConnectionOpened(ctx, destination, client)
	}
}

func TestDisabledFreedomConnectionOpenedLogAllocationBudget(t *testing.T) {
	client, server := stdnet.Pipe()
	defer client.Close()
	defer server.Close()
	ctx := context.Background()
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	allocations := testing.AllocsPerRun(1000, func() {
		logFreedomConnectionOpened(ctx, destination, client)
	})
	if allocations != 0 {
		t.Fatalf("disabled Freedom connection-opened log allocations = %.0f, want 0", allocations)
	}
}
