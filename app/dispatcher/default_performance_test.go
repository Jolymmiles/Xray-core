package dispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	corelog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type discardLogHandler struct{}

func (discardLogHandler) Handle(corelog.Message) {}

func init() {
	corelog.RegisterHandler(discardLogHandler{})
}

type performanceReader struct{}

func (*performanceReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }

type captureOutbound struct {
	reader buf.Reader
}

func (*captureOutbound) Start() error                         { return nil }
func (*captureOutbound) Close() error                         { return nil }
func (*captureOutbound) Tag() string                          { return "direct" }
func (*captureOutbound) SenderSettings() *serial.TypedMessage { return nil }
func (*captureOutbound) ProxySettings() *serial.TypedMessage  { return nil }
func (h *captureOutbound) Dispatch(_ context.Context, link *transport.Link) {
	h.reader = link.Reader
}

type fixedOutboundManager struct {
	handler outbound.Handler
}

func (*fixedOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (*fixedOutboundManager) Start() error      { return nil }
func (*fixedOutboundManager) Close() error      { return nil }
func (m *fixedOutboundManager) GetHandler(string) outbound.Handler {
	return m.handler
}
func (m *fixedOutboundManager) GetDefaultHandler() outbound.Handler { return m.handler }
func (*fixedOutboundManager) AddHandler(context.Context, outbound.Handler) error {
	return nil
}
func (*fixedOutboundManager) RemoveHandler(context.Context, string) error { return nil }
func (m *fixedOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	return []outbound.Handler{m.handler}
}

func newPerformanceDispatcher(handler outbound.Handler) *DefaultDispatcher {
	return &DefaultDispatcher{
		ohm:    &fixedOutboundManager{handler: handler},
		router: routing.DefaultRouter{},
		policy: policy.DefaultManager{},
		stats:  stats.NoopManager{},
	}
}

func performanceContext() context.Context {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	return session.ContextWithContent(ctx, &session.Content{})
}

func TestDispatchLinkWithoutSniffingOrStatsPreservesReader(t *testing.T) {
	handler := new(captureOutbound)
	dispatcher := newPerformanceDispatcher(handler)
	reader := new(performanceReader)
	link := &transport.Link{Reader: reader, Writer: buf.Discard}

	if err := dispatcher.DispatchLink(performanceContext(), net.TCPDestination(net.DomainAddress("example.com"), 443), link); err != nil {
		t.Fatal(err)
	}
	if handler.reader != reader {
		t.Fatalf("outbound reader = %T, want original %T", handler.reader, reader)
	}
}

func BenchmarkDispatchLinkWithoutSniffingOrStats(b *testing.B) {
	handler := new(captureOutbound)
	dispatcher := newPerformanceDispatcher(handler)
	ctx := performanceContext()
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	reader := new(performanceReader)
	link := &transport.Link{Reader: reader, Writer: buf.Discard}

	b.ReportAllocs()
	for b.Loop() {
		link.Reader = reader
		if err := dispatcher.DispatchLink(ctx, destination, link); err != nil {
			b.Fatal(err)
		}
	}
}
