package log_test

import (
	stdnet "net"
	"runtime/debug"
	"strings"
	"testing"

	corelog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
)

var vlessAccessMessageStringSink string

func BenchmarkVLESSAccessMessageString(b *testing.B) {
	message := &corelog.AccessMessage{
		From:   &stdnet.TCPAddr{IP: stdnet.IPv4(192, 0, 2, 1), Port: 12345},
		To:     xnet.TCPDestination(xnet.DomainAddress("example.com"), 443),
		Status: corelog.AccessAccepted,
		Reason: "",
		Email:  "user@example.com",
		Detour: "vless-in -> DIRECT",
	}
	b.ReportAllocs()
	for b.Loop() {
		vlessAccessMessageStringSink = message.String()
	}
}

func BenchmarkVLESSAccessSourceLifecycle(b *testing.B) {
	sourceAddr := &stdnet.TCPAddr{IP: stdnet.IPv4(192, 0, 2, 1), Port: 12345}
	sourceDestination := xnet.TCPDestination(xnet.IPAddress(sourceAddr.IP), xnet.Port(sourceAddr.Port))
	for _, benchmark := range []struct {
		name string
		from func() any
	}{
		{name: "tcp_addr", from: func() any { return sourceAddr }},
		{name: "destination_net_addr", from: func() any { return sourceDestination.NetAddr() }},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			message := &corelog.AccessMessage{To: "example.com:443", Status: corelog.AccessAccepted}
			b.ReportAllocs()
			for b.Loop() {
				message.From = benchmark.from()
				vlessAccessMessageStringSink = message.String()
			}
		})
	}
}

func BenchmarkVLESSAccessDestinationLifecycle(b *testing.B) {
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	for _, benchmark := range []struct {
		name string
		to   func() any
	}{
		{name: "destination", to: func() any { return destination }},
		{name: "destination_string", to: func() any { return destination.String() }},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			message := &corelog.AccessMessage{From: "192.0.2.1:12345", Status: corelog.AccessAccepted}
			b.ReportAllocs()
			for b.Loop() {
				message.To = benchmark.to()
				vlessAccessMessageStringSink = message.String()
			}
		})
	}
}

func BenchmarkVLESSAccessEndpointPairLifecycle(b *testing.B) {
	source := xnet.TCPDestination(xnet.IPv4Address([4]byte{192, 0, 2, 1}), 12345)
	target := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	message := &corelog.AccessMessage{Status: corelog.AccessAccepted, Email: "user@example.com", Detour: "vless-in -> DIRECT"}
	b.ReportAllocs()
	for b.Loop() {
		message.From, message.To = xnet.FormatAccessEndpoints(source, target)
		vlessAccessMessageStringSink = message.String()
	}
}

func TestVLESSAccessTypedEndpointAllocationBudget(t *testing.T) {
	if checkptrInstrumented() {
		t.Skip("checkptr instrumentation changes allocation counts")
	}
	source := xnet.TCPDestination(xnet.IPv4Address([4]byte{192, 0, 2, 1}), 12345)
	target := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	message := &corelog.AccessMessage{Status: corelog.AccessAccepted}
	allocations := testing.AllocsPerRun(1000, func() {
		message.FromString, message.ToString = xnet.FormatAccessEndpoints(source, target)
		vlessAccessMessageStringSink = message.String()
	})
	if allocations > 2 {
		t.Fatalf("typed VLESS access endpoints allocations = %.0f, want at most 2", allocations)
	}
}

func checkptrInstrumented() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-gcflags" && strings.Contains(setting.Value, "checkptr") {
			return true
		}
	}
	return false
}

func BenchmarkVLESSAccessTypedEndpointPairLifecycle(b *testing.B) {
	source := xnet.TCPDestination(xnet.IPv4Address([4]byte{192, 0, 2, 1}), 12345)
	target := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	message := &corelog.AccessMessage{Status: corelog.AccessAccepted, Email: "user@example.com", Detour: "vless-in -> DIRECT"}
	b.ReportAllocs()
	for b.Loop() {
		message.FromString, message.ToString = xnet.FormatAccessEndpoints(source, target)
		vlessAccessMessageStringSink = message.String()
	}
}
