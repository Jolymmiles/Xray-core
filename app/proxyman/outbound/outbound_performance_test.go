package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/serial"
	featureoutbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

type lookupHandler struct {
	tag string
}

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
