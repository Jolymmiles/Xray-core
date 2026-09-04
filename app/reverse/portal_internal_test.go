package reverse

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/outbound"

	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestPortalCloseWaitsForAdmittedHandler(t *testing.T) {
	portal := &Portal{state: portalOpen}
	if !portal.beginHandle() {
		t.Fatal("open portal rejected handler admission")
	}
	closed := make(chan struct{})
	go func() {
		_ = portal.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("portal close completed before admitted handler returned")
	default:
	}
	portal.endHandle()
	<-closed
	if portal.beginHandle() {
		t.Fatal("closed portal admitted a new handler")
	}
}

func TestPortalCloseStopsCarrierBeforeJoiningHandler(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	client, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	picker, err := NewStaticMuxPicker()
	if err != nil {
		t.Fatal(err)
	}
	picker.AddWorker(&PortalWorker{client: client})
	portal := &Portal{state: portalOpen, picker: picker}
	if !portal.beginHandle() {
		t.Fatal("open portal rejected carrier handler")
	}
	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})
	go func() {
		close(handlerStarted)
		<-client.WaitClosed()
		portal.endHandle()
		close(handlerDone)
	}()
	<-handlerStarted

	closeDone := make(chan error, 1)
	go func() { closeDone <- portal.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		_ = client.Close()
		<-closeDone
		t.Fatal("portal close waited for carrier handler before stopping its worker")
	}
	<-handlerDone
}

type blockingPortalHeartbeatWriter struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (w *blockingPortalHeartbeatWriter) WriteMultiBuffer(payload buf.MultiBuffer) error {
	buf.ReleaseMulti(payload)
	w.once.Do(func() { close(w.started) })
	<-w.closed
	return io.ErrClosedPipe
}

func (w *blockingPortalHeartbeatWriter) Close() error {
	select {
	case <-w.closed:
	default:
		close(w.closed)
	}
	return nil
}

func TestPortalWorkerCloseUnblocksAndJoinsHeartbeat(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	client, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	heartbeatWriter := &blockingPortalHeartbeatWriter{started: make(chan struct{}), closed: make(chan struct{})}
	worker := &PortalWorker{
		client: client,
		writer: heartbeatWriter,
		reader: reader,
		timer:  signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour),
	}
	worker.control = &task.Periodic{Execute: worker.heartbeat, Interval: time.Hour}
	t.Cleanup(func() {
		_ = heartbeatWriter.Close()
		_ = worker.Close()
	})
	heartbeatDone := make(chan error, 1)
	go func() { heartbeatDone <- worker.control.Start() }()
	<-heartbeatWriter.started

	closeDone := make(chan error, 1)
	go func() { closeDone <- worker.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("PortalWorker.Close did not unblock and join heartbeat")
	}
	if err := <-heartbeatDone; err == nil {
		t.Fatal("blocked heartbeat succeeded after worker close")
	}
	if err := worker.heartbeat(); err == nil {
		t.Fatal("worker admitted heartbeat after close")
	}
}

func TestStaticMuxPickerClosingRejectsDrainingFallback(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	client, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	picker := &StaticMuxPicker{workers: []*PortalWorker{{client: client, draining: true}}, closed: true}
	if got, err := picker.PickAvailable(); err == nil || got != nil {
		t.Fatalf("closing picker selected draining fallback: worker=%v err=%v", got, err)
	}
}

type portalOutboundManager struct {
	mu       sync.Mutex
	handlers map[string]outbound.Handler
}

func (*portalOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (*portalOutboundManager) Start() error      { return nil }
func (*portalOutboundManager) Close() error      { return nil }

func (m *portalOutboundManager) GetHandler(tag string) outbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handlers[tag]
}

func (m *portalOutboundManager) GetDefaultHandler() outbound.Handler { return nil }

func (m *portalOutboundManager) AddHandler(_ context.Context, handler outbound.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handlers == nil {
		m.handlers = make(map[string]outbound.Handler)
	}
	m.handlers[handler.Tag()] = handler
	return nil
}

func (m *portalOutboundManager) RemoveHandler(_ context.Context, tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.handlers, tag)
	return nil
}

func (m *portalOutboundManager) ListHandlers(context.Context) []outbound.Handler { return nil }

func TestPortalStartRejectsRegistrationAfterClose(t *testing.T) {
	manager := &portalOutboundManager{}
	portal, err := NewPortal(&PortalConfig{Tag: "reverse", Domain: "reverse.example"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err == nil {
		t.Fatal("closed portal accepted late outbound registration")
	}
	if handler := manager.GetHandler("reverse"); handler != nil {
		t.Fatal("closed portal left a late outbound handler registered")
	}
}

func TestStaticMuxPickerFallsBackToDrainingCarrier(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	client, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	picker := &StaticMuxPicker{workers: []*PortalWorker{{client: client, draining: true}}}
	got, err := picker.PickAvailable()
	if err != nil {
		t.Fatalf("draining carrier must remain available until its replacement arrives: %v", err)
	}
	if got != client {
		t.Fatal("picker returned a different carrier")
	}
}
