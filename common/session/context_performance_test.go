package session

import (
	"context"
	"testing"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
)

var (
	connectionContextSink context.Context
	accessContextSink     context.Context
	accessMessageSink     *log.AccessMessage
	forcedOutboundTagSink string
	sessionIDSink         c.ID
)

func BenchmarkNewSessionID(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		sessionIDSink = NewID()
	}
}

func BenchmarkNewSessionIDParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = NewID()
		}
	})
}

func TestContextWithConnectionMetadata(t *testing.T) {
	parentKey := struct{}{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), parentKey, "parent"))
	inbound := Inbound{Tag: "server"}
	outbound := Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 443)}
	content := Content{Protocol: "tls"}

	combined := ContextWithConnection(parent, 42, inbound, outbound, content)
	if got := c.IDFromContext(combined); got != 42 {
		t.Fatalf("session ID = %d, want 42", got)
	}
	if got := InboundFromContext(combined); got == nil || got.Tag != "server" {
		t.Fatalf("inbound = %+v", got)
	}
	outbounds := OutboundsFromContext(combined)
	if len(outbounds) != 1 || outbounds[0].Target.Port != 443 {
		t.Fatalf("outbounds = %+v", outbounds)
	}
	if got := ContentFromContext(combined); got == nil || got.Protocol != "tls" {
		t.Fatalf("content = %+v", got)
	}
	if got := combined.Value(parentKey); got != "parent" {
		t.Fatalf("parent value = %v", got)
	}
	cancel()
	select {
	case <-combined.Done():
	default:
		t.Fatal("parent cancellation was not propagated")
	}
}

func TestContextWithConnectionRoutingViewThroughWrapper(t *testing.T) {
	parent := ContextWithConnection(
		context.Background(),
		42,
		Inbound{
			Tag:    "vless-in",
			Source: net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 10}), 12345),
			Local:  net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 20}), 443),
		},
		Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 8443)},
		Content{Protocol: "tls"},
	)
	wrapped := context.WithValue(parent, struct{ name string }{"wrapper"}, true)
	routingContext := RoutingContextFromContext(wrapped)
	if routingContext == nil {
		t.Fatal("routing context not found through wrapper")
	}
	if routingContext.GetInboundTag() != "vless-in" || routingContext.GetSourcePort() != 12345 ||
		routingContext.GetLocalPort() != 443 || routingContext.GetTargetPort() != 8443 ||
		routingContext.GetTargetDomain() != "example.com" || routingContext.GetProtocol() != "tls" {
		t.Fatalf("unexpected routing context: inbound=%q source=%d local=%d target=%d domain=%q protocol=%q",
			routingContext.GetInboundTag(), routingContext.GetSourcePort(), routingContext.GetLocalPort(),
			routingContext.GetTargetPort(), routingContext.GetTargetDomain(), routingContext.GetProtocol())
	}
}

func TestContextWithAccessMessagePreservesWrapperSemantics(t *testing.T) {
	base := ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	wrapped := context.WithValue(base, struct{ name string }{"wrapper"}, true)
	message := new(log.AccessMessage)
	ctx := ContextWithAccessMessage(wrapped, message)
	if got := AccessMessageFromContext(ctx); got != message {
		t.Fatalf("access message = %p, want %p", got, message)
	}
	if message.SessionID != 42 {
		t.Fatalf("access session ID = %d, want 42", message.SessionID)
	}
}

func TestConnectionRoutingViewDoesNotBypassMetadataOverride(t *testing.T) {
	base := ContextWithConnection(
		context.Background(), 42, Inbound{Tag: "base"},
		Outbound{Target: net.TCPDestination(net.DomainAddress("base.example"), 443)},
		Content{Protocol: "base"},
	)
	override := []*Outbound{{Target: net.TCPDestination(net.DomainAddress("mux.example"), 8443)}}
	ctx := ContextWithOutbounds(base, override)
	if direct := RoutingContextFromContext(ctx); direct != nil {
		t.Fatal("base routing context bypassed outbound override")
	}
	if got := OutboundsFromContext(ctx); len(got) != 1 || got[0] != override[0] {
		t.Fatalf("outbounds = %+v, want override %+v", got, override)
	}

	content := &Content{Protocol: "mux"}
	ctx = ContextWithContent(base, content)
	if direct := RoutingContextFromContext(ctx); direct != nil {
		t.Fatal("base routing context bypassed content override")
	}
	if got := ContentFromContext(ctx); got != content {
		t.Fatalf("content = %p, want override %p", got, content)
	}
}

func TestConnectionMetadataFromContext(t *testing.T) {
	ctx := ContextWithConnection(
		context.Background(), 42, Inbound{Tag: "vless-in"},
		Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 443)},
		Content{Protocol: "tls"},
	)
	inbound, outbounds, content, routingContext := ConnectionMetadataFromContext(ctx)
	if inbound == nil || inbound.Tag != "vless-in" {
		t.Fatalf("inbound = %+v", inbound)
	}
	if len(outbounds) != 1 || outbounds[0].Target.Port != 443 {
		t.Fatalf("outbounds = %+v", outbounds)
	}
	if content == nil || content.Protocol != "tls" {
		t.Fatalf("content = %+v", content)
	}
	if routingContext == nil || routingContext.GetInboundTag() != "vless-in" {
		t.Fatalf("routing context = %+v", routingContext)
	}
}

func TestConnectionMetadataFromContextHonorsOverride(t *testing.T) {
	base := ContextWithConnection(context.Background(), 42, Inbound{Tag: "base"}, Outbound{}, Content{Protocol: "base"})
	override := []*Outbound{{Target: net.TCPDestination(net.DomainAddress("mux.example"), 8443)}}
	contentOverride := &Content{Protocol: "mux"}
	ctx := ContextWithContent(ContextWithOutbounds(base, override), contentOverride)

	inbound, outbounds, content, routingContext := ConnectionMetadataFromContext(ctx)
	if inbound == nil || inbound.Tag != "base" {
		t.Fatalf("inbound = %+v", inbound)
	}
	if len(outbounds) != 1 || outbounds[0] != override[0] {
		t.Fatalf("outbounds = %+v, want override", outbounds)
	}
	if content != contentOverride {
		t.Fatalf("content = %p, want %p", content, contentOverride)
	}
	if routingContext != nil {
		t.Fatalf("routing context bypassed metadata override: %+v", routingContext)
	}
}

func TestContextWithConnectionAllocationBudget(t *testing.T) {
	allocations := testing.AllocsPerRun(1000, func() {
		connectionContextSink = ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	})
	if allocations > 1 {
		t.Fatalf("ContextWithConnection allocations = %.0f, want at most 1", allocations)
	}
}

func BenchmarkContextWithConnection(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		connectionContextSink = ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	}
}

func TestPooledConnectionContextAllocationBudget(t *testing.T) {
	allocations := testing.AllocsPerRun(1000, func() {
		ctx := NewPooledConnectionContext(context.Background(), 42, Inbound{}, Outbound{}, Content{})
		connectionContextSink = ctx
		ReleasePooledConnectionContext(ctx)
	})
	if allocations != 0 {
		t.Fatalf("pooled connection context allocations = %.0f, want zero", allocations)
	}
}

func TestPooledConnectionContextClearsRetainedState(t *testing.T) {
	first := NewPooledConnectionContext(
		context.Background(), 42,
		Inbound{Tag: "first"}, Outbound{Target: net.TCPDestination(net.DomainAddress("first.example"), 443)},
		Content{Protocol: "tls"},
	)
	ContextWithAccessMessage(first, &log.AccessMessage{Email: "first@example.com"})
	ReleasePooledConnectionContext(first)

	second := NewPooledConnectionContext(context.Background(), 7, Inbound{}, Outbound{}, Content{})
	defer ReleasePooledConnectionContext(second)
	if got := c.IDFromContext(second); got != 7 {
		t.Fatalf("reused session ID = %d, want 7", got)
	}
	if inbound := InboundFromContext(second); inbound.Tag != "" || AccessMessageFromContext(second) != nil {
		t.Fatalf("reused context retained state: inbound=%+v access=%+v", inbound, AccessMessageFromContext(second))
	}
}

func BenchmarkPooledConnectionContext(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ctx := NewPooledConnectionContext(context.Background(), 42, Inbound{}, Outbound{}, Content{})
		connectionContextSink = ctx
		ReleasePooledConnectionContext(ctx)
	}
}

func BenchmarkConnectionContextWithAccessMessage(b *testing.B) {
	ctx := ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	message := new(log.AccessMessage)
	b.ReportAllocs()
	for b.Loop() {
		accessContextSink = ContextWithAccessMessage(ctx, message)
	}
}

func BenchmarkAccessMessageFromConnectionContext(b *testing.B) {
	ctx := ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	ctx = log.ContextWithAccessMessage(ctx, new(log.AccessMessage))
	b.ReportAllocs()
	for b.Loop() {
		accessMessageSink = AccessMessageFromContext(ctx)
	}
}

func TestConnectionContextWithAccessMessageAllocationBudget(t *testing.T) {
	ctx := ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	message := new(log.AccessMessage)
	allocations := testing.AllocsPerRun(1000, func() {
		accessContextSink = log.ContextWithAccessMessage(ctx, message)
	})
	if allocations != 0 {
		t.Fatalf("connection access context allocations = %.0f, want 0", allocations)
	}
}

func TestAccessMessageFromConnectionContext(t *testing.T) {
	message := new(log.AccessMessage)
	ctx := ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	ctx = log.ContextWithAccessMessage(ctx, message)
	if got := AccessMessageFromContext(ctx); got != message {
		t.Fatalf("direct access message = %p, want %p", got, message)
	}

	wrapped := context.WithValue(ctx, struct{ name string }{"wrapper"}, true)
	if got := AccessMessageFromContext(wrapped); got != message {
		t.Fatalf("wrapped access message = %p, want %p", got, message)
	}
}

func BenchmarkGetForcedOutboundTagFromConnectionContext(b *testing.B) {
	ctx := ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	ctx = context.WithValue(ctx, struct{ name string }{"wrapper"}, true)
	b.ReportAllocs()
	for b.Loop() {
		forcedOutboundTagSink = GetForcedOutboundTagFromContext(ctx)
	}
}

func TestTakeForcedOutboundTagFromContent(t *testing.T) {
	content := new(Content)
	content.SetAttribute("forcedOutboundTag", "DIRECT")
	if got := TakeForcedOutboundTagFromContent(content); got != "DIRECT" {
		t.Fatalf("forced outbound tag = %q, want DIRECT", got)
	}
	if got := TakeForcedOutboundTagFromContent(content); got != "" {
		t.Fatalf("consumed forced outbound tag = %q, want empty", got)
	}
	if got := TakeForcedOutboundTagFromContent(nil); got != "" {
		t.Fatalf("nil content forced outbound tag = %q, want empty", got)
	}
}

func BenchmarkSetForcedOutboundTagOnConnectionContext(b *testing.B) {
	ctx := ContextWithConnection(context.Background(), 42, Inbound{}, Outbound{}, Content{})
	ctx = context.WithValue(ctx, struct{ name string }{"wrapper"}, true)
	ctx = SetForcedOutboundTagToContext(ctx, "DIRECT")
	b.ReportAllocs()
	for b.Loop() {
		accessContextSink = SetForcedOutboundTagToContext(ctx, "DIRECT")
	}
}
