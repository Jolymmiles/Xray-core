package dispatcher

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	corelog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type discardLogHandler struct{}

func (discardLogHandler) Handle(corelog.Message) {}
func (discardLogHandler) Enabled(severity corelog.Severity) bool {
	return severity <= corelog.Severity_Warning
}

type accessCaptureLogHandler struct {
	messages chan *corelog.AccessMessage
}

func (h accessCaptureLogHandler) Handle(message corelog.Message) {
	if access, ok := message.(*corelog.AccessMessage); ok {
		h.messages <- access
	}
}

func (accessCaptureLogHandler) Enabled(corelog.Severity) bool { return false }

func init() {
	corelog.RegisterHandler(discardLogHandler{})
}

type performanceReader struct{}

func (*performanceReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }

type singleBufferTimeoutReader struct {
	payload []byte
}

type fixedMultiTimeoutReader struct {
	mb buf.MultiBuffer
}

func (r *fixedMultiTimeoutReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.mb
	r.mb = nil
	return mb, nil
}

func (r *fixedMultiTimeoutReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

func (r *singleBufferTimeoutReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return buf.MultiBuffer{buf.FromBytes(r.payload)}, nil
}

func (r *singleBufferTimeoutReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

var (
	sniffResultBenchmarkSink          SniffResult
	snifferBenchmarkSink              *Sniffer
	snifferValueBenchmarkSink         Sniffer
	shouldOverrideBenchmarkSink       bool
	shouldOverrideDomainBenchmarkSink string
)

type neverDomainMatcher struct{}

func (neverDomainMatcher) Match(string) []uint32 { return nil }
func (neverDomainMatcher) MatchAny(string) bool  { return false }

var (
	detourBenchmarkSink  string
	cachedReaderByteSink byte
)

type countingSniffResult struct {
	protocol    string
	domain      string
	domainCalls int
}

func (r *countingSniffResult) Protocol() string { return r.protocol }

func (r *countingSniffResult) Domain() string {
	r.domainCalls++
	return r.domain
}

func TestShouldOverrideReturnsEvaluatedDomain(t *testing.T) {
	result := &countingSniffResult{protocol: "http", domain: "example.com"}
	request := session.SniffingRequest{OverrideDestinationForProtocol: []string{"http"}}
	destination := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443)

	domain, override := new(DefaultDispatcher).shouldOverride(context.Background(), result, request, destination)
	if !override {
		t.Fatal("expected destination override")
	}
	if domain != result.domain {
		t.Fatalf("unexpected domain: got %q, want %q", domain, result.domain)
	}
	if result.domainCalls != 1 {
		t.Fatalf("Domain called %d times, want 1", result.domainCalls)
	}
}

type fixedSniffResult struct {
	protocol string
	domain   string
}

func (r fixedSniffResult) Protocol() string { return r.protocol }
func (r fixedSniffResult) Domain() string   { return r.domain }

type captureOutbound struct {
	reader buf.Reader
}

type statelessOutbound struct{}

func (*statelessOutbound) Start() error                              { return nil }
func (*statelessOutbound) Close() error                              { return nil }
func (*statelessOutbound) Tag() string                               { return "direct" }
func (*statelessOutbound) SenderSettings() *serial.TypedMessage      { return nil }
func (*statelessOutbound) ProxySettings() *serial.TypedMessage       { return nil }
func (*statelessOutbound) Dispatch(context.Context, *transport.Link) {}

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

type fixedRouteTagRouter struct {
	routing.DefaultRouter
	outboundTag string
	ruleTag     string
}

func (r *fixedRouteTagRouter) PickRouteTag(routing.Context) (string, string, error) {
	return r.outboundTag, r.ruleTag, nil
}

type fixedSniffingRequirementRouter struct {
	routing.DefaultRouter
	needsAttributes bool
}

func (r *fixedSniffingRequirementRouter) NeedsSniffingAttributes() bool {
	return r.needsAttributes
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

func TestDispatchLinkRecordsHandlerTagOnCurrentOutbound(t *testing.T) {
	handler := new(captureOutbound)
	dispatcher := newPerformanceDispatcher(handler)
	ctx := performanceContext()
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) != 1 {
		t.Fatalf("outbounds = %d, want 1", len(outbounds))
	}
	link := &transport.Link{Reader: new(performanceReader), Writer: buf.Discard}

	if err := dispatcher.DispatchLink(ctx, net.TCPDestination(net.DomainAddress("example.com"), 443), link); err != nil {
		t.Fatal(err)
	}
	if outbounds[0].Tag != handler.Tag() {
		t.Fatalf("outbound tag = %q, want %q", outbounds[0].Tag, handler.Tag())
	}
}

func TestDispatchLinkSnapshotsAccessMessageWithActualStreamDestination(t *testing.T) {
	capture := accessCaptureLogHandler{messages: make(chan *corelog.AccessMessage, 1)}
	corelog.RegisterHandler(capture)
	t.Cleanup(func() { corelog.RegisterHandler(discardLogHandler{}) })

	handler := new(captureOutbound)
	dispatcher := newPerformanceDispatcher(handler)
	destination := net.TCPDestination(net.IPAddress([]byte{100, 85, 127, 181}), 80)
	ctx := session.ContextWithConnection(
		context.Background(), 42, session.Inbound{Tag: "vless-in"},
		session.Outbound{Target: destination}, session.Content{},
	)
	carrier := &corelog.AccessMessage{
		FromString: "tcp:192.0.2.1:50000",
		ToString:   "tcp:sp.mux.sing-box.arpa:444",
		Status:     corelog.AccessAccepted,
	}
	ctx = corelog.ContextWithAccessMessage(ctx, carrier)
	link := &transport.Link{Reader: new(performanceReader), Writer: buf.Discard}

	if err := dispatcher.DispatchLink(ctx, destination, link); err != nil {
		t.Fatal(err)
	}
	recorded := <-capture.messages
	if recorded == carrier {
		t.Fatal("dispatcher recorded the shared carrier AccessMessage pointer")
	}
	if carrier.ToString != "tcp:sp.mux.sing-box.arpa:444" || carrier.Detour != "" {
		t.Fatalf("shared carrier message was mutated: %+v", carrier)
	}
	if !recorded.HasTarget || recorded.Target.String() != "tcp:100.85.127.181:80" {
		t.Fatalf("recorded destination = %#v, want actual SMUX stream destination", recorded.Target)
	}
	if recorded.Detour != "vless-in >> direct" {
		t.Fatalf("recorded detour = %q, want %q", recorded.Detour, "vless-in >> direct")
	}
	if recorded.Component != "app/dispatcher" || recorded.Inbound != "vless-in" || recorded.Outbound != "direct" || recorded.SessionID != 42 {
		t.Fatalf("structured route metadata = %+v", recorded)
	}
}

func TestConcurrentMuxStreamsDoNotMutateSharedAccessCarrier(t *testing.T) {
	capture := accessCaptureLogHandler{messages: make(chan *corelog.AccessMessage, 2)}
	corelog.RegisterHandler(capture)
	t.Cleanup(func() { corelog.RegisterHandler(discardLogHandler{}) })

	dispatcher := newPerformanceDispatcher(new(statelessOutbound))
	carrier := &corelog.AccessMessage{
		FromString: "tcp:192.0.2.1:50000",
		ToString:   "tcp:sp.mux.sing-box.arpa:444",
		Status:     corelog.AccessAccepted,
	}
	ctx := session.ContextWithConnection(
		context.Background(), 42, session.Inbound{Tag: "vless-in"},
		session.Outbound{}, session.Content{},
	)
	ctx = corelog.ContextWithAccessMessage(ctx, carrier)
	destinations := []net.Destination{
		net.TCPDestination(net.IPAddress([]byte{100, 85, 127, 181}), 80),
		net.TCPDestination(net.DomainAddress("example.com"), 443),
	}
	var dispatches sync.WaitGroup
	for _, destination := range destinations {
		destination := destination
		streamContext := session.SubContextFromMuxInbound(ctx)
		dispatches.Add(1)
		go func() {
			defer dispatches.Done()
			link := &transport.Link{Reader: new(performanceReader), Writer: buf.Discard}
			if err := dispatcher.DispatchLink(streamContext, destination, link); err != nil {
				t.Errorf("DispatchLink(%s): %v", destination, err)
			}
		}()
	}
	dispatches.Wait()

	got := make(map[string]struct{}, len(destinations))
	for range destinations {
		recorded := <-capture.messages
		got[recorded.Target.String()] = struct{}{}
		if recorded.Detour != "vless-in >> direct" {
			t.Fatalf("recorded detour = %q", recorded.Detour)
		}
	}
	for _, destination := range destinations {
		if _, found := got[destination.String()]; !found {
			t.Fatalf("missing logical stream destination %q; got=%v", destination, got)
		}
	}
	if carrier.ToString != "tcp:sp.mux.sing-box.arpa:444" || carrier.Detour != "" || carrier.HasTarget {
		t.Fatalf("shared SMUX carrier was mutated: %+v", carrier)
	}
}

func TestDispatchLinkWithoutSniffingOrStatsAllocationBudget(t *testing.T) {
	handler := new(captureOutbound)
	dispatcher := newPerformanceDispatcher(handler)
	ctx := performanceContext()
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	reader := new(performanceReader)
	link := &transport.Link{Reader: reader, Writer: buf.Discard}

	allocations := testing.AllocsPerRun(1000, func() {
		link.Reader = reader
		if err := dispatcher.DispatchLink(ctx, destination, link); err != nil {
			t.Fatal(err)
		}
	})
	if allocations > 1 {
		t.Fatalf("warning-level DispatchLink allocations = %.0f, want at most 1", allocations)
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

func BenchmarkDispatchLinkWithAccessMessage(b *testing.B) {
	handler := new(captureOutbound)
	dispatcher := newPerformanceDispatcher(handler)
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	ctx := session.ContextWithConnection(
		context.Background(),
		42,
		session.Inbound{Tag: "vless-in"},
		session.Outbound{Target: destination},
		session.Content{},
	)
	access := new(corelog.AccessMessage)
	ctx = corelog.ContextWithAccessMessage(ctx, access)
	reader := new(performanceReader)
	link := &transport.Link{Reader: reader, Writer: buf.Discard}

	b.ReportAllocs()
	for b.Loop() {
		link.Reader = reader
		access.Detour = ""
		if err := dispatcher.DispatchLink(ctx, destination, link); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDispatchLinkWithRouteTagPicker(b *testing.B) {
	handler := new(captureOutbound)
	manager := &fixedOutboundManager{handler: handler}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(nil, manager, &fixedRouteTagRouter{outboundTag: "direct", ruleTag: "static"}, policy.DefaultManager{}, stats.NoopManager{}); err != nil {
		b.Fatal(err)
	}
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	ctx := session.ContextWithConnection(context.Background(), 42, session.Inbound{Tag: "vless-in"}, session.Outbound{Target: destination}, session.Content{})
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

func BenchmarkConfigureSniffingAttributes(b *testing.B) {
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(nil, nil, &fixedSniffingRequirementRouter{}, policy.DefaultManager{}, stats.NoopManager{}); err != nil {
		b.Fatal(err)
	}
	content := new(session.Content)
	b.ReportAllocs()
	for b.Loop() {
		dispatcher.configureSniffingAttributes(content)
	}
}

func TestConfigureSniffingAttributes(t *testing.T) {
	for _, test := range []struct {
		name            string
		needsAttributes bool
		wantSkip        bool
	}{
		{name: "no attribute rules", needsAttributes: false, wantSkip: true},
		{name: "attribute rules", needsAttributes: true, wantSkip: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dispatcher := new(DefaultDispatcher)
			router := &fixedSniffingRequirementRouter{needsAttributes: test.needsAttributes}
			if err := dispatcher.Init(nil, nil, router, policy.DefaultManager{}, stats.NoopManager{}); err != nil {
				t.Fatal(err)
			}
			content := &session.Content{SkipSniffingAttributes: !test.wantSkip}
			dispatcher.configureSniffingAttributes(content)
			if content.SkipSniffingAttributes != test.wantSkip {
				t.Fatalf("SkipSniffingAttributes = %t, want %t", content.SkipSniffingAttributes, test.wantSkip)
			}
		})
	}
}

func TestDispatchLinkWithAccessMessageAllocationBudget(t *testing.T) {
	handler := new(captureOutbound)
	dispatcher := newPerformanceDispatcher(handler)
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	ctx := session.ContextWithConnection(
		context.Background(), 42, session.Inbound{Tag: "vless-in"},
		session.Outbound{Target: destination}, session.Content{},
	)
	access := new(corelog.AccessMessage)
	ctx = corelog.ContextWithAccessMessage(ctx, access)
	reader := new(performanceReader)
	link := &transport.Link{Reader: reader, Writer: buf.Discard}
	allocations := testing.AllocsPerRun(1000, func() {
		link.Reader = reader
		access.Detour = ""
		if err := dispatcher.DispatchLink(ctx, destination, link); err != nil {
			t.Fatal(err)
		}
	})
	if allocations > 1 {
		t.Fatalf("DispatchLink access allocations = %.0f, want at most 1", allocations)
	}
}

func TestDetourFormatting(t *testing.T) {
	dispatcher := new(DefaultDispatcher)
	for _, test := range []struct {
		inbound  string
		outbound string
		route    int
		want     string
	}{
		{"", "DIRECT", 0, "DIRECT"},
		{"vless-in", "DIRECT", 0, "vless-in >> DIRECT"},
		{"vless-in", "DIRECT", 1, "vless-in ==> DIRECT"},
		{"vless-in", "DIRECT", 2, "vless-in -> DIRECT"},
	} {
		if got := dispatcher.detour(test.inbound, test.outbound, test.route); got != test.want {
			t.Fatalf("detour(%q, %q, %d) = %q, want %q", test.inbound, test.outbound, test.route, got, test.want)
		}
	}
}

func TestDetourCachePreservesConcurrentEntries(t *testing.T) {
	dispatcher := new(DefaultDispatcher)
	const entries = 64
	var wait sync.WaitGroup
	wait.Add(entries)
	for index := range entries {
		go func() {
			defer wait.Done()
			inbound := fmt.Sprintf("in-%d", index)
			outbound := fmt.Sprintf("out-%d", index)
			want := inbound + " >> " + outbound
			if got := dispatcher.detour(inbound, outbound, 0); got != want {
				t.Errorf("detour(%q, %q) = %q, want %q", inbound, outbound, got, want)
			}
		}()
	}
	wait.Wait()
	for index := range entries {
		inbound := fmt.Sprintf("in-%d", index)
		outbound := fmt.Sprintf("out-%d", index)
		want := inbound + " >> " + outbound
		if got := dispatcher.detour(inbound, outbound, 0); got != want {
			t.Fatalf("cached detour(%q, %q) = %q, want %q", inbound, outbound, got, want)
		}
	}
}

func BenchmarkDetourCacheHit(b *testing.B) {
	dispatcher := new(DefaultDispatcher)
	dispatcher.detour("vless-in", "DIRECT", 0)
	b.ReportAllocs()
	for b.Loop() {
		detourBenchmarkSink = dispatcher.detour("vless-in", "DIRECT", 0)
	}
}

func BenchmarkDetourCacheSize(b *testing.B) {
	for _, size := range []int{1, 8, 32, 128} {
		b.Run(fmt.Sprintf("%d/HitFirst", size), func(b *testing.B) {
			dispatcher := populatedDetourDispatcher(size)
			b.ReportAllocs()
			for b.Loop() {
				detourBenchmarkSink = dispatcher.detour("in-0", "out-0", 0)
			}
		})
		b.Run(fmt.Sprintf("%d/HitLast", size), func(b *testing.B) {
			dispatcher := populatedDetourDispatcher(size)
			inbound := fmt.Sprintf("in-%d", size-1)
			outbound := fmt.Sprintf("out-%d", size-1)
			b.ReportAllocs()
			for b.Loop() {
				detourBenchmarkSink = dispatcher.detour(inbound, outbound, 0)
			}
		})
	}
}

func populatedDetourDispatcher(size int) *DefaultDispatcher {
	dispatcher := new(DefaultDispatcher)
	for index := range size {
		dispatcher.detour(fmt.Sprintf("in-%d", index), fmt.Sprintf("out-%d", index), 0)
	}
	return dispatcher
}

func BenchmarkCachedReaderCacheSingleBuffer(b *testing.B) {
	payload := make([]byte, 2048)
	payload[len(payload)-1] = 1
	reader := &cachedReader{reader: &singleBufferTimeoutReader{payload: payload}}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		cached, err := reader.Cache(time.Second)
		if err != nil {
			b.Fatal(err)
		}
		cachedReaderByteSink = cached[len(payload)-1]
		buf.ReleaseMulti(reader.readInternal())
	}
}

func TestCachedReaderFirstBufferAllocationBudget(t *testing.T) {
	payload := []byte("first cache payload")
	reader := &cachedReader{reader: &singleBufferTimeoutReader{payload: payload}}
	allocations := testing.AllocsPerRun(1000, func() {
		cached, err := reader.Cache(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		cachedReaderByteSink = cached[len(cached)-1]
		buf.ReleaseMulti(reader.readInternal())
	})
	if allocations > 2 {
		t.Fatalf("first cache allocations = %.0f, want at most 2", allocations)
	}
}

func TestCachedReaderCacheOwnership(t *testing.T) {
	t.Run("single buffer is snapshotted", func(t *testing.T) {
		payload := []byte("single")
		reader := &cachedReader{reader: &singleBufferTimeoutReader{payload: payload}}
		cached, err := reader.Cache(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cached, payload) || &cached[0] == &payload[0] {
			t.Fatalf("cached payload = %q, want independent snapshot of %q", cached, payload)
		}
		buf.ReleaseMulti(reader.readInternal())
		if reader.scratch != nil {
			t.Fatal("single-buffer cache allocated scratch")
		}
	})

	t.Run("multiple buffers use released scratch", func(t *testing.T) {
		reader := &cachedReader{reader: &fixedMultiTimeoutReader{mb: buf.MultiBuffer{
			buf.FromBytes([]byte("multi")),
			buf.FromBytes([]byte("buffer")),
		}}}
		cached, err := reader.Cache(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if string(cached) != "multibuffer" {
			t.Fatalf("cached payload = %q, want multibuffer", cached)
		}
		if reader.scratch == nil {
			t.Fatal("multi-buffer cache did not allocate scratch")
		}
		buf.ReleaseMulti(reader.readInternal())
		if reader.scratch != nil {
			t.Fatal("multi-buffer scratch retained after cache handoff")
		}
	})
}

func BenchmarkSnifferCachedSingleBuffer(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	dispatcher := &DefaultDispatcher{snifferTemplate: newSniffer(ctx)}
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		reader := newCachedReader(&singleBufferTimeoutReader{payload: payload})
		result, err := sniff(ctx, reader, false, net.Network_TCP, dispatcher.connectionSniffer(ctx))
		if err != nil {
			b.Fatal(err)
		}
		sniffResultBenchmarkSink = result
		buf.ReleaseMulti(reader.readInternal())
	}
}

func BenchmarkSnifferCachedSingleBufferAttributes(b *testing.B) {
	parent := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	dispatcher := &DefaultDispatcher{snifferTemplate: newSniffer(parent)}
	ctx := session.ContextWithConnection(parent, 42, session.Inbound{}, session.Outbound{}, session.Content{})
	content := session.ContentFromContext(ctx)
	content.SkipSniffingAttributes = true
	payload := []byte("GET /index HTTP/1.1\r\nHost: example.com\r\nUser-Agent: benchmark\r\nAccept: */*\r\n\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		content.Attributes = nil
		reader := newCachedReader(&singleBufferTimeoutReader{payload: payload})
		result, err := sniff(ctx, reader, false, net.Network_TCP, dispatcher.connectionSniffer(ctx))
		if err != nil {
			b.Fatal(err)
		}
		sniffResultBenchmarkSink = result
		buf.ReleaseMulti(reader.readInternal())
	}
}

func TestSnifferCachedSingleBufferAllocationBudget(t *testing.T) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	allocations := testing.AllocsPerRun(1000, func() {
		reader := cachedReader{reader: &singleBufferTimeoutReader{payload: payload}}
		result, err := sniffer(ctx, &reader, false, net.Network_TCP)
		if err != nil || result == nil {
			t.Fatalf("sniffer result = %v, error = %v", result, err)
		}
		buf.ReleaseMulti(reader.readInternal())
	})
	// The cached reader owns a connection-specific lifetime and must not be
	// recycled while an outbound I/O goroutine can still reference it. The
	// seventh allocation is Cache's stable snapshot: returning the pooled
	// buffer directly races with Interrupt releasing it.
	if allocations > 7 {
		t.Fatalf("single-buffer sniff allocations = %.0f, want at most 7", allocations)
	}
}

func TestCachedReadersDoNotShareState(t *testing.T) {
	first := newCachedReader(&singleBufferTimeoutReader{payload: []byte("first")})
	if _, err := first.Cache(time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { buf.ReleaseMulti(first.readInternal()) })

	second := newCachedReader(&singleBufferTimeoutReader{payload: []byte("second")})
	t.Cleanup(func() { buf.ReleaseMulti(second.readInternal()) })
	if first == second {
		t.Fatal("cached readers unexpectedly share an instance")
	}
	if second.cache != nil || second.scratch != nil {
		t.Fatalf("new reader retained cache=%v scratch=%v", second.cache, second.scratch)
	}
	payload, err := second.Cache(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "second" {
		t.Fatalf("new reader payload = %q, want second", payload)
	}
}

func TestSniffMetadataWithoutMetadataSniffersAllocationBudget(t *testing.T) {
	sniffer := &Sniffer{sniffer: defaultProtocolSniffers[:]}
	allocations := testing.AllocsPerRun(1000, func() {
		sniffer.sniffer = defaultProtocolSniffers[:]
		result, err := sniffer.SniffMetadata(context.Background())
		if result != nil || err != common.ErrNoClue {
			t.Fatalf("SniffMetadata result = %v, error = %v", result, err)
		}
	})
	if allocations != 0 {
		t.Fatalf("SniffMetadata allocations = %.0f, want 0", allocations)
	}
}

func TestSnifferFastHTTPShortcutPreservesResult(t *testing.T) {
	called := 0
	fast := func(context.Context, []byte) (SniffResult, error) {
		called++
		return fixedSniffResult{protocol: "http", domain: "example.com"}, nil
	}
	sniffer := Sniffer{
		sniffer:  []protocolSnifferWithMetadata{{protocolSniffer: fast, fastHTTP: true, network: net.Network_TCP}},
		fastHTTP: fast,
	}
	result, err := sniffer.Sniff(context.Background(), []byte("GET / HTTP/1.1\r\n\r\n"), net.Network_TCP)
	if err != nil {
		t.Fatal(err)
	}
	if result.Domain() != "example.com" || called != 1 {
		t.Fatalf("fast HTTP result = %q after %d calls", result.Domain(), called)
	}
}

func BenchmarkNewSnifferHTTP(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		result, err := NewSniffer(ctx).Sniff(ctx, payload, net.Network_TCP)
		if err != nil {
			b.Fatal(err)
		}
		sniffResultBenchmarkSink = result
	}
}

func BenchmarkNewSniffer(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	b.ReportAllocs()
	for b.Loop() {
		snifferBenchmarkSink = NewSniffer(ctx)
	}
}

func BenchmarkNewSnifferValue(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	b.ReportAllocs()
	for b.Loop() {
		snifferValueBenchmarkSink = newSniffer(ctx)
	}
}

func BenchmarkSnifferTemplateCopy(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	dispatcher := &DefaultDispatcher{snifferTemplate: newSniffer(ctx)}
	b.ReportAllocs()
	for b.Loop() {
		snifferValueBenchmarkSink = dispatcher.connectionSniffer(ctx)
	}
}

func TestNewSnifferAllocationBudget(t *testing.T) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	allocations := testing.AllocsPerRun(1000, func() {
		snifferBenchmarkSink = NewSniffer(ctx)
	})
	if allocations > 1 {
		t.Fatalf("NewSniffer allocations = %.0f, want at most 1", allocations)
	}
}

func BenchmarkSnifferHTTP(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	sniffer := NewSniffer(ctx)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		result, err := sniffer.Sniff(ctx, payload, net.Network_TCP)
		if err != nil {
			b.Fatal(err)
		}
		sniffResultBenchmarkSink = result
	}
}

func BenchmarkSnifferTLSOrder(b *testing.B) {
	payload := dispatcherTLSClientHello("example.com")
	sniffer := Sniffer{sniffer: defaultProtocolSniffers[:]}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		result, err := sniffer.Sniff(context.Background(), payload, net.Network_TCP)
		if err != nil {
			b.Fatal(err)
		}
		sniffResultBenchmarkSink = result
	}
}

func dispatcherTLSClientHello(serverName string) []byte {
	nameLength := len(serverName)
	serverNameListLength := 1 + 2 + nameLength
	serverNameExtensionLength := 2 + serverNameListLength
	extensionsLength := 4 + serverNameExtensionLength
	handshakeLength := 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensionsLength
	record := make([]byte, 5+handshakeLength)
	record[0], record[1], record[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(handshakeLength))
	handshake := record[5:]
	handshake[0] = 0x01
	handshake[1] = byte((handshakeLength - 4) >> 16)
	handshake[2] = byte((handshakeLength - 4) >> 8)
	handshake[3] = byte(handshakeLength - 4)
	handshake[4], handshake[5] = 0x03, 0x03
	offset := 4 + 2 + 32
	handshake[offset] = 0
	offset++
	binary.BigEndian.PutUint16(handshake[offset:offset+2], 2)
	offset += 2
	handshake[offset], handshake[offset+1] = 0x13, 0x01
	offset += 2
	handshake[offset], handshake[offset+1] = 1, 0
	offset += 2
	binary.BigEndian.PutUint16(handshake[offset:offset+2], uint16(extensionsLength))
	offset += 2
	binary.BigEndian.PutUint16(handshake[offset:offset+2], 0)
	binary.BigEndian.PutUint16(handshake[offset+2:offset+4], uint16(serverNameExtensionLength))
	offset += 4
	binary.BigEndian.PutUint16(handshake[offset:offset+2], uint16(serverNameListLength))
	offset += 2
	handshake[offset] = 0
	binary.BigEndian.PutUint16(handshake[offset+1:offset+3], uint16(nameLength))
	copy(handshake[offset+3:], serverName)
	return record
}

func BenchmarkShouldOverrideRemnaConfig(b *testing.B) {
	rules, err := geodata.ParseDomainRules([]string{
		"courier.push.apple.com",
		"dlg.io.mi.com",
		"push.apple.com",
		"api.push.apple.com",
		`regexp:(^|\.)wa\.me$`,
		`regexp:(^|\.)whatsapp-plus\.info$`,
		`regexp:(^|\.)whatsapp-plus\.me$`,
		`regexp:(^|\.)whatsapp-plus\.net$`,
		`regexp:(^|\.)whatsapp\.cc$`,
		`regexp:(^|\.)whatsapp\.com$`,
		`regexp:(^|\.)whatsapp\.info$`,
		`regexp:(^|\.)whatsapp\.net$`,
		`regexp:(^|\.)whatsapp\.orgs$`,
		`regexp:(^|\.)whatsapp\.tv$`,
		`regexp:(^|\.)whatsappbrand\.com$`,
	}, geodata.Domain_Domain)
	if err != nil {
		b.Fatal(err)
	}
	matcher, err := geodata.DomainReg.BuildDomainMatcher(rules)
	if err != nil {
		b.Fatal(err)
	}
	request := session.SniffingRequest{
		ExcludeForDomain:               matcher,
		OverrideDestinationForProtocol: []string{"http", "tls"},
	}
	dispatcher := new(DefaultDispatcher)
	ctx := context.Background()
	destination := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443)

	benchmarks := []struct {
		name   string
		result *fixedSniffResult
	}{
		{"MissHTTP", &fixedSniffResult{protocol: "http", domain: "example.com"}},
		{"MissTLS", &fixedSniffResult{protocol: "tls", domain: "example.com"}},
		{"ExactExcluded", &fixedSniffResult{protocol: "tls", domain: "courier.push.apple.com"}},
		{"SuffixExcluded", &fixedSniffResult{protocol: "tls", domain: "web.whatsapp.com"}},
		{"UppercaseSuffixExcluded", &fixedSniffResult{protocol: "tls", domain: "WEB.WHATSAPP.COM"}},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, shouldOverrideBenchmarkSink = dispatcher.shouldOverride(ctx, benchmark.result, request, destination)
			}
		})
	}
}

func BenchmarkShouldOverrideDomainReuse(b *testing.B) {
	dispatcher := new(DefaultDispatcher)
	ctx := context.Background()
	request := session.SniffingRequest{OverrideDestinationForProtocol: []string{"http"}}
	destination := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443)
	var result SniffResult = fixedSniffResult{protocol: "http", domain: "example.com"}

	b.Run("LegacyCaller", func(b *testing.B) {
		for b.Loop() {
			_, override := dispatcher.shouldOverride(ctx, result, request, destination)
			if override {
				shouldOverrideDomainBenchmarkSink = result.Domain()
			}
		}
	})
	b.Run("ReuseDomain", func(b *testing.B) {
		for b.Loop() {
			domain, override := dispatcher.shouldOverride(ctx, result, request, destination)
			if override {
				shouldOverrideDomainBenchmarkSink = domain
			}
		}
	})
}

func BenchmarkShouldOverrideSniffedHTTP(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	result, err := NewSniffer(ctx).Sniff(ctx, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), net.Network_TCP)
	if err != nil {
		b.Fatal(err)
	}
	dispatcher := new(DefaultDispatcher)
	request := session.SniffingRequest{OverrideDestinationForProtocol: []string{"http", "tls"}}
	destination := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		_, shouldOverrideBenchmarkSink = dispatcher.shouldOverride(ctx, result, request, destination)
	}
}

func BenchmarkShouldOverrideNormalizedHTTPDomain(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	normalized, err := NewSniffer(ctx).Sniff(ctx, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), net.Network_TCP)
	if err != nil {
		b.Fatal(err)
	}
	legacy := &fixedSniffResult{protocol: normalized.Protocol(), domain: normalized.Domain()}
	dispatcher := new(DefaultDispatcher)
	request := session.SniffingRequest{
		ExcludeForDomain:               neverDomainMatcher{},
		OverrideDestinationForProtocol: []string{"http", "tls"},
		OverrideProtocolMask:           session.SniffingOverrideHTTP | session.SniffingOverrideTLS,
	}
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	for _, benchmark := range []struct {
		name   string
		result SniffResult
	}{
		{name: "legacy-lowercase-scan", result: legacy},
		{name: "normalized-marker", result: normalized},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, shouldOverrideBenchmarkSink = dispatcher.shouldOverride(ctx, benchmark.result, request, destination)
			}
		})
	}
}

func BenchmarkShouldOverrideSniffedTLS(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	result, err := NewSniffer(ctx).Sniff(ctx, dispatcherTLSClientHello("example.com"), net.Network_TCP)
	if err != nil {
		b.Fatal(err)
	}
	dispatcher := new(DefaultDispatcher)
	request := session.SniffingRequest{OverrideDestinationForProtocol: []string{"http", "tls"}}
	destination := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443)
	b.ReportAllocs()
	for b.Loop() {
		_, shouldOverrideBenchmarkSink = dispatcher.shouldOverride(ctx, result, request, destination)
	}
}

func BenchmarkShouldOverrideNormalizedTLSDomain(b *testing.B) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	normalized, err := NewSniffer(ctx).Sniff(ctx, dispatcherTLSClientHello("example.com"), net.Network_TCP)
	if err != nil {
		b.Fatal(err)
	}
	legacy := &fixedSniffResult{protocol: normalized.Protocol(), domain: normalized.Domain()}
	dispatcher := new(DefaultDispatcher)
	request := session.SniffingRequest{
		ExcludeForDomain:               neverDomainMatcher{},
		OverrideDestinationForProtocol: []string{"http", "tls"},
		OverrideProtocolMask:           session.SniffingOverrideHTTP | session.SniffingOverrideTLS,
	}
	destination := net.TCPDestination(net.IPv4Address([4]byte{192, 0, 2, 1}), 443)
	for _, benchmark := range []struct {
		name   string
		result SniffResult
	}{
		{name: "legacy-lowercase-scan", result: legacy},
		{name: "normalized-marker", result: normalized},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, shouldOverrideBenchmarkSink = dispatcher.shouldOverride(ctx, benchmark.result, request, destination)
			}
		})
	}
}

func TestTLSNormalizedDomainMarker(t *testing.T) {
	for _, test := range []struct {
		name       string
		serverName string
		wantDomain string
	}{
		{name: "lowercase", serverName: "example.com", wantDomain: "example.com"},
		{name: "uppercase", serverName: "Example.COM", wantDomain: "example.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
			result, err := NewSniffer(ctx).Sniff(ctx, dispatcherTLSClientHello(test.serverName), net.Network_TCP)
			if err != nil {
				t.Fatal(err)
			}
			normalized, ok := result.(snifferNormalizedDomain)
			if !ok || !normalized.DomainNormalized() || result.Domain() != test.wantDomain {
				t.Fatalf("result domain = %q, normalized = %t, present = %t; want %q, true, true", result.Domain(), ok && normalized.DomainNormalized(), ok, test.wantDomain)
			}
		})
	}
}
