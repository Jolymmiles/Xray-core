package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	featureoutbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type lookupHandler struct {
	tag string
}

type performanceOutbound struct{}

func (*performanceOutbound) Process(context.Context, *transport.Link, internet.Dialer) error {
	return nil
}

type performanceLinkReader struct{}

func (*performanceLinkReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }

var _ proxy.Outbound = (*performanceOutbound)(nil)

func (*lookupHandler) Start() error                              { return nil }
func (*lookupHandler) Close() error                              { return nil }
func (h *lookupHandler) Tag() string                             { return h.tag }
func (*lookupHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (*lookupHandler) ProxySettings() *serial.TypedMessage       { return nil }
func (*lookupHandler) Dispatch(context.Context, *transport.Link) {}

func TestHandlerLookupDoesNotWaitForWriterLock(t *testing.T) {
	manager, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := &lookupHandler{tag: "direct"}
	if err := manager.AddHandler(context.Background(), handler); err != nil {
		t.Fatal(err)
	}

	manager.access.Lock()
	done := make(chan featureoutbound.Handler, 1)
	go func() { done <- manager.GetHandler("direct") }()
	select {
	case got := <-done:
		manager.access.Unlock()
		if got != handler {
			t.Fatalf("handler = %v, want %v", got, handler)
		}
	case <-time.After(100 * time.Millisecond):
		manager.access.Unlock()
		t.Fatal("handler lookup waited for writer lock")
	}
}

func TestHandlerLookupSnapshotTracksMutations(t *testing.T) {
	manager, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	first := &lookupHandler{tag: "first"}
	second := &lookupHandler{tag: "second"}
	if err := manager.AddHandler(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := manager.AddHandler(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if manager.GetDefaultHandler() != first || manager.GetHandler("second") != second {
		t.Fatal("snapshot did not expose added handlers")
	}
	if err := manager.RemoveHandler(context.Background(), "first"); err != nil {
		t.Fatal(err)
	}
	if manager.GetDefaultHandler() != nil || manager.GetHandler("first") != nil {
		t.Fatal("snapshot did not expose removed default handler")
	}
}

func BenchmarkGetHandler(b *testing.B) {
	manager, err := New(context.Background(), nil)
	if err != nil {
		b.Fatal(err)
	}
	if err := manager.AddHandler(context.Background(), &lookupHandler{tag: "direct"}); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if manager.GetHandler("direct") == nil {
			b.Fatal("handler not found")
		}
	}
}

func BenchmarkHandlerDispatchWithoutSenderSettings(b *testing.B) {
	handler := &Handler{proxy: new(performanceOutbound)}
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	ctx := session.ContextWithConnection(
		context.Background(), 42, session.Inbound{},
		session.Outbound{Target: destination}, session.Content{},
	)
	reader := new(performanceLinkReader)
	link := &transport.Link{Reader: reader, Writer: buf.Discard}
	b.ReportAllocs()
	for b.Loop() {
		handler.Dispatch(ctx, link)
	}
}
