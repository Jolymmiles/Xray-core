// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// detachedDispatcher models a real outbound handler: it returns only when its
// own context is cancelled, and never inspects the inbound link. A dispatcher
// that unblocks as soon as the carrier stream errors would hide the leak under
// test, because a dead session already fails every stream read and write.
type detachedDispatcher struct {
	started chan struct{}
}

func (*detachedDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, io.ErrClosedPipe
}

func (d *detachedDispatcher) DispatchLink(ctx context.Context, _ X.Destination, _ *transport.Link) error {
	select {
	case d.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func (*detachedDispatcher) Start() error      { return nil }
func (*detachedDispatcher) Close() error      { return nil }
func (*detachedDispatcher) Type() interface{} { return routing.DispatcherType() }

// startLeakTestCarrier completes the carrier handshake and returns a client
// session whose peer is service.NewConnection, plus the channel carrying that
// call's result.
func startLeakTestCarrier(t *testing.T, service *Service, ctx context.Context) (*localsmux.Session, net.Conn, chan error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(ctx, serverConn) }()
	if err := writeCarrierRequest(clientConn, protocolSMUX, nil); err != nil {
		_ = clientConn.Close()
		t.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := localsmux.Client(clientConn, config)
	if err != nil {
		_ = clientConn.Close()
		t.Fatal(err)
	}
	return session, clientConn, result
}

// openDispatchedStream drives one stream through the service handshake and
// waits until its handler has entered the dispatcher.
func openDispatchedStream(t *testing.T, session *localsmux.Session, started chan struct{}) *localsmux.Stream {
	t.Helper()
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	if err := writeStreamRequest(stream, 0, destination); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not enter the dispatcher")
	}
	return stream
}

// A carrier that dies while a stream handler is still dispatching must not pin
// that handler forever. NewConnection waits for its handlers before returning,
// so a handler that only observes its context keeps the accept goroutine, the
// handler goroutine and the carrier connection alive for the whole process.
func TestServiceStopsStreamHandlersWhenCarrierDies(t *testing.T) {
	dispatcher := &detachedDispatcher{started: make(chan struct{}, 1)}
	service := NewService(dispatcher)
	service.streamHandshakeTimeout = time.Second

	session, clientConn, result := startLeakTestCarrier(t, service, context.Background())
	openDispatchedStream(t, session, dispatcher.started)

	// Abrupt carrier death, exactly like a dropped inbound TCP connection. The
	// parent context stays live, so cancellation must come from the service.
	_ = session.Close()
	_ = clientConn.Close()

	select {
	case <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("NewConnection did not return after the carrier died: stream handlers are leaked")
	}
}

// The same guarantee, driven by cancelling the carrier context instead of
// killing the connection.
func TestServiceStopsStreamHandlersOnContextCancellation(t *testing.T) {
	dispatcher := &detachedDispatcher{started: make(chan struct{}, 1)}
	service := NewService(dispatcher)
	service.streamHandshakeTimeout = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, clientConn, result := startLeakTestCarrier(t, service, ctx)
	defer session.Close()
	defer clientConn.Close()
	openDispatchedStream(t, session, dispatcher.started)

	cancel()
	select {
	case <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("NewConnection did not return after context cancellation: stream handlers are leaked")
	}
}

// Goroutine accounting over repeated carrier churn. Every carrier here dies
// abruptly with an in-flight stream handler, which is the shape that leaks.
func TestServiceLeaksNoGoroutinesAcrossCarriers(t *testing.T) {
	dispatcher := &detachedDispatcher{started: make(chan struct{}, 1)}
	service := NewService(dispatcher)
	service.streamHandshakeTimeout = time.Second

	runCarrier := func() {
		session, clientConn, result := startLeakTestCarrier(t, service, context.Background())
		openDispatchedStream(t, session, dispatcher.started)
		_ = session.Close()
		_ = clientConn.Close()
		select {
		case <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("NewConnection did not return after the carrier died")
		}
	}

	// Warm up first so one-time package state is not counted as a leak.
	runCarrier()
	baseline := settledGoroutines()

	const carriers = 16
	for range carriers {
		runCarrier()
	}

	// settledGoroutines already waits for teardown to stabilise, so the slack
	// only covers runtime-owned goroutines. A leak costs ~3 per carrier.
	if leaked := settledGoroutines() - baseline; leaked > 2 {
		t.Fatalf("goroutine count grew by %d over %d carriers", leaked, carriers)
	}
}

// stuckDispatcher ignores its context and its link alike, modelling a handler
// wedged inside a third-party call. Neither cancelling the handler context nor
// failing the session can release it.
type stuckDispatcher struct {
	started chan struct{}
	release chan struct{}
}

func (*stuckDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, io.ErrClosedPipe
}

func (d *stuckDispatcher) DispatchLink(context.Context, X.Destination, *transport.Link) error {
	select {
	case d.started <- struct{}{}:
	default:
	}
	<-d.release
	return nil
}

func (*stuckDispatcher) Start() error      { return nil }
func (*stuckDispatcher) Close() error      { return nil }
func (*stuckDispatcher) Type() interface{} { return routing.DispatcherType() }

// SMUX wire keepalive is disabled for interop, so a client that vanishes without
// a FIN leaves the session read loop parked in io.ReadFull forever. Nothing else
// reaps that carrier.
func TestServiceReapsSilentCarrier(t *testing.T) {
	dispatcher := &detachedDispatcher{started: make(chan struct{}, 1)}
	service := NewService(dispatcher)
	service.carrierIdleTimeout = 100 * time.Millisecond

	session, clientConn, result := startLeakTestCarrier(t, service, context.Background())
	defer session.Close()
	defer clientConn.Close()

	// The carrier handshake completed; the client now sends nothing at all.
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("NewConnection returned nil for a silent carrier, want an idle error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("silent carrier was never reaped")
	}
}

// A handler that observes neither its context nor its stream must not hold the
// carrier goroutines and connection for the lifetime of the process.
func TestServiceDoesNotPinCarrierOnStuckHandler(t *testing.T) {
	dispatcher := &stuckDispatcher{started: make(chan struct{}, 1), release: make(chan struct{})}
	defer close(dispatcher.release)
	service := NewService(dispatcher)
	service.streamHandshakeTimeout = time.Second
	service.handlerDrainTimeout = 100 * time.Millisecond

	session, clientConn, result := startLeakTestCarrier(t, service, context.Background())
	openDispatchedStream(t, session, dispatcher.started)
	_ = session.Close()
	_ = clientConn.Close()

	select {
	case <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("a handler stuck outside the context and the stream pinned the carrier")
	}
}

// settledGoroutines waits for the goroutine count to stop changing so that
// still-unwinding teardown is not mistaken for a leak.
func settledGoroutines() int {
	previous := runtime.NumGoroutine()
	for range 50 {
		time.Sleep(20 * time.Millisecond)
		runtime.GC()
		current := runtime.NumGoroutine()
		if current == previous {
			return current
		}
		previous = current
	}
	return previous
}
