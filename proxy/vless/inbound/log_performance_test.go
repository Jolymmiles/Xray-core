package inbound

import (
	"context"
	"testing"

	corelog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

var vlessAccountErrorSink error
var vlessAccountErrorStringSink string

type warningPerformanceLogHandler struct{}

func (warningPerformanceLogHandler) Handle(corelog.Message) {}
func (warningPerformanceLogHandler) Enabled(severity corelog.Severity) bool {
	return severity <= corelog.Severity_Warning
}

func BenchmarkDisabledVLESSRequestLogs(b *testing.B) {
	corelog.RegisterHandler(warningPerformanceLogHandler{})
	ctx := context.Background()
	request := &protocol.RequestHeader{
		Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("example.com"),
		Port:    443,
	}
	b.ReportAllocs()
	for b.Loop() {
		logFirstBufferLength(ctx, 34)
		logReceivedRequest(ctx, request)
	}
}

func BenchmarkAccountFlowMismatchError(b *testing.B) {
	id := protocol.NewID(uuid.New())
	b.Run("Construct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorSink = accountFlowMismatchError(id, "xtls-rprx-vision")
		}
	})
	b.Run("String", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorStringSink = accountFlowMismatchError(id, "xtls-rprx-vision").Error()
		}
	})
}

func TestAccountFlowMismatchErrorText(t *testing.T) {
	id := protocol.NewID(uuid.New())
	want := "proxy/vless/inbound: account " + id.String() + " is not able to use the flow xtls-rprx-vision"
	if got := accountFlowMismatchError(id, "xtls-rprx-vision").Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func BenchmarkAccountEmptyFlowError(b *testing.B) {
	id := protocol.NewID(uuid.New())
	b.Run("Construct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorSink = accountEmptyFlowError(id)
		}
	})
	b.Run("String", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorStringSink = accountEmptyFlowError(id).Error()
		}
	})
}

func TestAccountEmptyFlowErrorText(t *testing.T) {
	id := protocol.NewID(uuid.New())
	want := "proxy/vless/inbound: account " + id.String() + " is rejected since the client flow is empty. Note that the pure TLS proxy has certain TLS in TLS characters."
	if got := accountEmptyFlowError(id).Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func BenchmarkUnknownRequestFlowError(b *testing.B) {
	b.Run("Construct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorSink = unknownRequestFlowError("unsupported-flow")
		}
	})
	b.Run("String", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorStringSink = unknownRequestFlowError("unsupported-flow").Error()
		}
	})
}

func TestUnknownRequestFlowErrorText(t *testing.T) {
	const want = "proxy/vless/inbound: unknown request flow unsupported-flow"
	if got := unknownRequestFlowError("unsupported-flow").Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func BenchmarkFlowDoesNotSupportUDPError(b *testing.B) {
	b.Run("Construct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorSink = flowDoesNotSupportUDPError("xtls-rprx-vision")
		}
	})
	b.Run("String", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorStringSink = flowDoesNotSupportUDPError("xtls-rprx-vision").Error()
		}
	})
}

func TestFlowDoesNotSupportUDPErrorText(t *testing.T) {
	const want = "proxy/vless/inbound: xtls-rprx-vision doesn't support UDP"
	if got := flowDoesNotSupportUDPError("xtls-rprx-vision").Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func BenchmarkInvalidOuterTLSVersionError(b *testing.B) {
	b.Run("Construct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorSink = invalidOuterTLSVersionError("xtls-rprx-vision", 0x0303)
		}
	})
	b.Run("String", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorStringSink = invalidOuterTLSVersionError("xtls-rprx-vision", 0x0303).Error()
		}
	})
}

func TestInvalidOuterTLSVersionErrorText(t *testing.T) {
	const want = "proxy/vless/inbound: failed to use xtls-rprx-vision, found outer tls version 771"
	if got := invalidOuterTLSVersionError("xtls-rprx-vision", 0x0303).Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func BenchmarkForwardProxyNotAllowedError(b *testing.B) {
	id := protocol.NewID(uuid.New())
	b.Run("Construct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorSink = forwardProxyNotAllowedError(id)
		}
	})
	b.Run("String", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vlessAccountErrorStringSink = forwardProxyNotAllowedError(id).Error()
		}
	})
}

func TestForwardProxyNotAllowedErrorText(t *testing.T) {
	id := protocol.NewID(uuid.New())
	want := "proxy/vless/inbound: for safety reasons, user " + id.String() + " is not allowed to use forward proxy"
	if got := forwardProxyNotAllowedError(id).Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}
