// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/transport"
)

type gatedHandshakeConn struct {
	net.Conn
	readStarted  chan struct{}
	readReturned chan struct{}
	allowReturn  chan struct{}
	startOnce    sync.Once
	returnOnce   sync.Once
}

func (c *gatedHandshakeConn) Read(payload []byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	n, err := c.Conn.Read(payload)
	c.returnOnce.Do(func() { close(c.readReturned) })
	<-c.allowReturn
	return n, err
}

type joinedCloseErrorConn struct {
	net.Conn
	closeErr error
	started  chan struct{}
	once     sync.Once
}

func (c *joinedCloseErrorConn) Read(payload []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(payload)
}

func (c *joinedCloseErrorConn) Close() error {
	_ = c.Conn.Close()
	return errors.Join(net.ErrClosed, c.closeErr)
}

func TestServiceClosePreservesAbnormalJoinedCarrierError(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	clientConnection, serverConnection := net.Pipe()
	closeErr := errors.New("flush failed")
	carrier := &joinedCloseErrorConn{Conn: serverConnection, closeErr: closeErr, started: make(chan struct{})}
	connectionResult := make(chan error, 1)
	go func() { connectionResult <- service.NewConnection(context.Background(), carrier) }()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		_ = service.Close()
	})
	waitSignal(t, carrier.started, "carrier handshake did not start")

	err := service.Close()
	if !errors.Is(err, closeErr) {
		t.Fatalf("Service.Close error = %v, want joined %v", err, closeErr)
	}
	if errors.Is(err, net.ErrClosed) {
		t.Fatalf("Service.Close error = %v, want normal close component filtered", err)
	}
	waitResult(t, connectionResult, "NewConnection did not complete")
}

type wrappedJoinedCloseErrorConn struct {
	*joinedCloseErrorConn
}

func (c *wrappedJoinedCloseErrorConn) Close() error {
	return fmt.Errorf("transport close: %w", c.joinedCloseErrorConn.Close())
}

func TestServiceCloseFiltersNormalErrorNestedWithAbnormalCarrierError(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	clientConnection, serverConnection := net.Pipe()
	closeErr := errors.New("flush failed")
	baseCarrier := &joinedCloseErrorConn{Conn: serverConnection, closeErr: closeErr, started: make(chan struct{})}
	carrier := &wrappedJoinedCloseErrorConn{joinedCloseErrorConn: baseCarrier}
	connectionResult := make(chan error, 1)
	go func() { connectionResult <- service.NewConnection(context.Background(), carrier) }()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		_ = service.Close()
	})
	waitSignal(t, carrier.started, "carrier handshake did not start")

	err := service.Close()
	if !errors.Is(err, closeErr) {
		t.Fatalf("Service.Close error = %v, want joined %v", err, closeErr)
	}
	if errors.Is(err, net.ErrClosed) {
		t.Fatalf("Service.Close error = %v, want nested normal close component filtered", err)
	}
	waitResult(t, connectionResult, "NewConnection did not complete")
}

type orderedCloseGate struct {
	mu           sync.Mutex
	calls        int
	firstStarted chan struct{}
	secondCalled chan struct{}
	allowFirst   chan struct{}
}

func (g *orderedCloseGate) close(conn net.Conn) error {
	g.mu.Lock()
	g.calls++
	call := g.calls
	g.mu.Unlock()
	switch call {
	case 1:
		close(g.firstStarted)
		<-g.allowFirst
	case 2:
		close(g.secondCalled)
	}
	return conn.Close()
}

type orderedCloseConn struct {
	net.Conn
	gate *orderedCloseGate
}

func (c *orderedCloseConn) Close() error { return c.gate.close(c.Conn) }

func TestServiceCloseStartsAllCarrierInterruptionsBeforeWaiting(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	gate := &orderedCloseGate{
		firstStarted: make(chan struct{}),
		secondCalled: make(chan struct{}),
		allowFirst:   make(chan struct{}),
	}
	connectionResults := make(chan error, 2)
	clients := make([]net.Conn, 0, 2)
	for range 2 {
		clientConnection, serverConnection := net.Pipe()
		clients = append(clients, clientConnection)
		carrier := &orderedCloseConn{Conn: serverConnection, gate: gate}
		go func() { connectionResults <- service.NewConnection(context.Background(), carrier) }()
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.allowFirst) }) }
	t.Cleanup(func() {
		release()
		for _, client := range clients {
			_ = client.Close()
		}
		_ = service.Close()
	})

	for _, client := range clients {
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := client.Write([]byte{0}); err != nil {
			t.Fatalf("start carrier handshake: %v", err)
		}
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- service.Close() }()
	waitSignal(t, gate.firstStarted, "Service.Close did not start the first carrier interruption")
	waitSignal(t, gate.secondCalled, "Service.Close waited for the first carrier Close before interrupting the second")
	select {
	case err := <-closeResult:
		t.Fatalf("Service.Close returned while the first carrier Close was gated: %v", err)
	default:
	}

	release()
	for range 2 {
		waitResult(t, connectionResults, "NewConnection did not complete after carrier interruption")
	}
	if err := waitResult(t, closeResult, "Service.Close did not wait for all carrier shutdowns"); err != nil {
		t.Fatalf("Service.Close error = %v", err)
	}
}

func TestServiceCloseInterruptsCarrierHandshakeAndWaitsForNewConnection(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	clientConnection, serverConnection := net.Pipe()
	carrier := &gatedHandshakeConn{
		Conn:         serverConnection,
		readStarted:  make(chan struct{}),
		readReturned: make(chan struct{}),
		allowReturn:  make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(carrier.allowReturn) }) }
	t.Cleanup(func() {
		release()
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})

	connectionResult := make(chan error, 1)
	go func() { connectionResult <- service.NewConnection(context.Background(), carrier) }()
	waitSignal(t, carrier.readStarted, "carrier handshake did not start")

	closeResult := make(chan error, 1)
	go func() { closeResult <- service.Close() }()
	waitSignal(t, carrier.readReturned, "Service.Close did not interrupt the carrier handshake")
	select {
	case err := <-closeResult:
		t.Fatalf("Service.Close returned before NewConnection completed: %v", err)
	default:
	}

	release()
	waitResult(t, connectionResult, "NewConnection did not complete")
	if err := waitResult(t, closeResult, "Service.Close did not complete"); err != nil {
		t.Fatalf("Service.Close error = %v", err)
	}
}

func TestServiceCloseLinearizesAdmittedAndRejectedCarriers(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	firstClient, firstServer := net.Pipe()
	firstCarrier := &gatedHandshakeConn{
		Conn:         firstServer,
		readStarted:  make(chan struct{}),
		readReturned: make(chan struct{}),
		allowReturn:  make(chan struct{}),
	}
	firstResult := make(chan error, 1)
	go func() { firstResult <- service.NewConnection(context.Background(), firstCarrier) }()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(firstCarrier.allowReturn) }) }
	t.Cleanup(func() {
		release()
		_ = firstClient.Close()
		_ = firstServer.Close()
		_ = service.Close()
	})
	waitSignal(t, firstCarrier.readStarted, "first carrier was not admitted before shutdown")

	closeResult := make(chan error, 1)
	go func() { closeResult <- service.Close() }()
	waitSignal(t, firstCarrier.readReturned, "Service.Close did not interrupt the admitted carrier")

	secondClient, secondServer := net.Pipe()
	secondCarrier := &observedConn{Conn: secondServer}
	t.Cleanup(func() {
		_ = secondClient.Close()
		_ = secondServer.Close()
	})
	if err := service.NewConnection(context.Background(), secondCarrier); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("crossing NewConnection error = %v, want net.ErrClosed", err)
	}
	reads, closes := secondCarrier.counts()
	if reads != 0 || closes != 1 {
		t.Fatalf("rejected carrier reads/closes = %d/%d, want 0/1", reads, closes)
	}

	release()
	waitResult(t, firstResult, "admitted NewConnection did not complete")
	if err := waitResult(t, closeResult, "Service.Close did not complete after crossing admission"); err != nil {
		t.Fatalf("Service.Close error = %v", err)
	}
}

type lifecycleBlockingDispatcher struct {
	*echoDispatcher
	started  chan struct{}
	canceled chan struct{}
	finished chan struct{}
	release  chan struct{}
}

func (d *lifecycleBlockingDispatcher) DispatchLink(ctx context.Context, _ X.Destination, _ *transport.Link) error {
	close(d.started)
	<-ctx.Done()
	close(d.canceled)
	<-d.release
	close(d.finished)
	return ctx.Err()
}

type terminalPresenceDispatcher struct {
	*lifecycleBlockingDispatcher
	provider *terminalPresenceProvider
}

func (d *terminalPresenceDispatcher) PresenceProvider() session.PresenceProvider { return d.provider }

type terminalPresenceProvider struct {
	tracker *terminalPresenceTracker
}

func (p *terminalPresenceProvider) SnapshotPresence(context.Context) session.PresenceScope {
	return session.NewPresenceScope(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("192.0.2.44"),
	}, p.tracker)
}

type terminalPresenceTracker struct {
	activated  chan struct{}
	closeStart chan struct{}
	allowClose chan struct{}
	closed     chan struct{}
}

func (t *terminalPresenceTracker) Prepare(session.PresenceSubject) session.PresenceReservation {
	return &terminalPresenceReservation{tracker: t}
}

type terminalPresenceReservation struct {
	tracker *terminalPresenceTracker
}

func (r *terminalPresenceReservation) Activate() session.PresenceLease {
	close(r.tracker.activated)
	return &terminalPresenceLease{
		closeStart: r.tracker.closeStart,
		allowClose: r.tracker.allowClose,
		closed:     r.tracker.closed,
	}
}

func (r *terminalPresenceReservation) Handoff(old session.PresenceLease) session.PresenceLease {
	if old != nil {
		old.Close()
	}
	return r.Activate()
}

func (r *terminalPresenceReservation) HandoffAll(old []session.PresenceLease) []session.PresenceLease {
	for _, lease := range old {
		if lease != nil {
			lease.Close()
		}
	}
	return nil
}

func (*terminalPresenceReservation) Abort() {}

type terminalPresenceLease struct {
	closeStart chan struct{}
	allowClose chan struct{}
	closed     chan struct{}
	once       sync.Once
}

func (l *terminalPresenceLease) Close() {
	l.once.Do(func() {
		close(l.closeStart)
		<-l.allowClose
		close(l.closed)
	})
}

func TestServiceCloseWaitsForMPLPresenceLeaseAndDispatcher(t *testing.T) {
	tracker := &terminalPresenceTracker{
		activated:  make(chan struct{}),
		closeStart: make(chan struct{}),
		allowClose: make(chan struct{}),
		closed:     make(chan struct{}),
	}
	blocking := &lifecycleBlockingDispatcher{
		echoDispatcher: &echoDispatcher{target: make(chan X.Destination, 1)},
		started:        make(chan struct{}),
		canceled:       make(chan struct{}),
		finished:       make(chan struct{}),
		release:        make(chan struct{}),
	}
	dispatcher := &terminalPresenceDispatcher{
		lifecycleBlockingDispatcher: blocking,
		provider:                    &terminalPresenceProvider{tracker: tracker},
	}
	service := NewService(dispatcher)
	clientConnection, serverConnection := net.Pipe()
	connectionResult := make(chan error, 1)
	go func() { connectionResult <- service.NewConnection(context.Background(), serverConnection) }()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocking.release) }) }
	var releaseLeaseOnce sync.Once
	releaseLease := func() { releaseLeaseOnce.Do(func() { close(tracker.allowClose) }) }
	t.Cleanup(func() {
		release()
		releaseLease()
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		_ = service.Close()
	})

	if err := writeCarrierRequest(clientConnection, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	clientSession, err := mplsmux.Client(clientConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if err := writeStreamRequest(stream, 0, X.TCPDestination(X.DomainAddress("example.com"), 443)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, tracker.activated, "MPL presence lease was not activated")
	waitSignal(t, blocking.started, "MPL dispatcher did not start")

	closeResult := make(chan error, 1)
	go func() { closeResult <- service.Close() }()
	waitSignal(t, blocking.canceled, "Service.Close did not cancel the MPL dispatcher")
	select {
	case <-tracker.closed:
		t.Fatal("presence lease closed before its dispatcher returned")
	default:
	}
	select {
	case err := <-closeResult:
		t.Fatalf("Service.Close returned before dispatcher and presence lease completion: %v", err)
	default:
	}

	release()
	waitSignal(t, blocking.finished, "MPL dispatcher did not finish")
	waitSignal(t, tracker.closeStart, "MPL presence lease Close did not start")
	select {
	case err := <-closeResult:
		t.Fatalf("Service.Close returned while the presence lease Close was gated: %v", err)
	default:
	}
	releaseLease()
	waitSignal(t, tracker.closed, "MPL presence lease did not close")
	waitResult(t, connectionResult, "NewConnection did not join dispatcher completion")
	if err := waitResult(t, closeResult, "Service.Close did not join presence completion"); err != nil {
		t.Fatalf("Service.Close error = %v", err)
	}
}

func TestServiceCloseCancelsMPLHandlerAndWaitsForCompletion(t *testing.T) {
	dispatcher := &lifecycleBlockingDispatcher{
		echoDispatcher: &echoDispatcher{target: make(chan X.Destination, 1)},
		started:        make(chan struct{}),
		canceled:       make(chan struct{}),
		finished:       make(chan struct{}),
		release:        make(chan struct{}),
	}
	service := NewService(dispatcher)
	clientConnection, serverConnection := net.Pipe()
	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	connectionResult := make(chan error, 1)
	go func() { connectionResult <- service.NewConnection(carrierCtx, serverConnection) }()

	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(dispatcher.release) }) }
	t.Cleanup(func() {
		cancelCarrier()
		release()
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		_ = service.Close()
	})

	if err := writeCarrierRequest(clientConnection, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	clientSession, err := mplsmux.Client(clientConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if err := writeStreamRequest(stream, 0, X.TCPDestination(X.DomainAddress("example.com"), 443)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, dispatcher.started, "MPL handler did not enter the dispatcher")

	closeResult := make(chan error, 1)
	go func() { closeResult <- service.Close() }()
	waitSignal(t, dispatcher.canceled, "Service.Close did not cancel the MPL handler context")
	select {
	case err := <-closeResult:
		t.Fatalf("Service.Close returned before the MPL handler completed: %v", err)
	default:
	}

	release()
	waitSignal(t, dispatcher.finished, "MPL handler did not finish")
	waitResult(t, connectionResult, "NewConnection did not wait for the MPL handler")
	if err := waitResult(t, closeResult, "Service.Close did not wait for the MPL handler"); err != nil {
		t.Fatalf("Service.Close error = %v", err)
	}
}

func TestServiceCloseRacingActiveMPLCarrierFailureCompletesOnce(t *testing.T) {
	dispatcher := &lifecycleBlockingDispatcher{
		echoDispatcher: &echoDispatcher{target: make(chan X.Destination, 1)},
		started:        make(chan struct{}),
		canceled:       make(chan struct{}),
		finished:       make(chan struct{}),
		release:        make(chan struct{}),
	}
	service := NewService(dispatcher)
	clientConnection, serverConnection := net.Pipe()
	carrier := &observedConn{Conn: serverConnection}
	connectionResult := make(chan error, 1)
	go func() { connectionResult <- service.NewConnection(context.Background(), carrier) }()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(dispatcher.release) }) }
	t.Cleanup(func() {
		release()
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		_ = service.Close()
	})

	if err := writeCarrierRequest(clientConnection, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	clientSession, err := mplsmux.Client(clientConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStreamRequest(stream, 0, X.TCPDestination(X.DomainAddress("example.com"), 443)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, dispatcher.started, "MPL dispatcher did not start")

	start := make(chan struct{})
	peerFailureResult := make(chan error, 1)
	closeResult := make(chan error, 1)
	go func() {
		<-start
		peerFailureResult <- clientSession.Close()
	}()
	go func() {
		<-start
		closeResult <- service.Close()
	}()
	close(start)
	waitSignal(t, dispatcher.canceled, "carrier failure racing Service.Close did not cancel the dispatcher")
	select {
	case err := <-closeResult:
		t.Fatalf("Service.Close returned before the active MPL handler: %v", err)
	default:
	}

	release()
	waitSignal(t, dispatcher.finished, "active MPL dispatcher did not finish")
	waitResult(t, peerFailureResult, "MPL peer failure did not complete")
	waitResult(t, connectionResult, "NewConnection deadlocked during carrier failure")
	if err := waitResult(t, closeResult, "Service.Close deadlocked during carrier failure"); err != nil {
		t.Fatalf("Service.Close error = %v", err)
	}
	_, closes := carrier.counts()
	if closes != 1 {
		t.Fatalf("physical carrier closes = %d, want exactly 1", closes)
	}
	_ = stream.Close()
}

type observedConn struct {
	net.Conn
	mu         sync.Mutex
	readCount  int
	closeCount int
}

func (c *observedConn) Read(payload []byte) (int, error) {
	c.mu.Lock()
	c.readCount++
	c.mu.Unlock()
	return c.Conn.Read(payload)
}

func (c *observedConn) Close() error {
	c.mu.Lock()
	c.closeCount++
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *observedConn) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readCount, c.closeCount
}

func TestServiceRejectsConnectionAfterClosePreservesAbnormalJoinedCarrierError(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	clientConnection, serverConnection := net.Pipe()
	closeErr := errors.New("flush failed")
	carrier := &joinedCloseErrorConn{Conn: serverConnection, closeErr: closeErr, started: make(chan struct{})}
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})

	err := service.NewConnection(context.Background(), carrier)
	if !errors.Is(err, net.ErrClosed) || !errors.Is(err, closeErr) {
		t.Fatalf("NewConnection error = %v, want net.ErrClosed joined with %v", err, closeErr)
	}
}

func TestServiceRejectsConnectionAfterClose(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	clientConnection, serverConnection := net.Pipe()
	carrier := &observedConn{Conn: serverConnection}
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})

	err := service.NewConnection(context.Background(), carrier)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("NewConnection error = %v, want net.ErrClosed", err)
	}
	reads, closes := carrier.counts()
	if reads != 0 {
		t.Fatalf("post-close carrier handshake reads = %d, want 0", reads)
	}
	if closes != 1 {
		t.Fatalf("post-close physical closes = %d, want 1", closes)
	}
	_ = clientConnection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientConnection.Read(make([]byte, 1)); err == nil {
		t.Fatal("post-close carrier peer remained open")
	}
}

func TestServiceConcurrentCloseAndAdmission(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	const connectionCount = 32
	const closeCount = 8
	start := make(chan struct{})
	connectionResults := make(chan error, connectionCount)
	closeResults := make(chan error, closeCount)
	clients := make([]net.Conn, 0, connectionCount)
	for range connectionCount {
		clientConnection, serverConnection := net.Pipe()
		clients = append(clients, clientConnection)
		go func() {
			<-start
			connectionResults <- service.NewConnection(context.Background(), serverConnection)
		}()
	}
	t.Cleanup(func() {
		for _, client := range clients {
			_ = client.Close()
		}
		_ = service.Close()
	})
	for range closeCount {
		go func() {
			<-start
			closeResults <- service.Close()
		}()
	}
	close(start)

	for range closeCount {
		if err := waitResult(t, closeResults, "concurrent Service.Close did not complete"); err != nil {
			t.Fatalf("Service.Close error = %v", err)
		}
	}
	for range connectionCount {
		if err := waitResult(t, connectionResults, "concurrent NewConnection did not complete"); err == nil {
			t.Fatal("concurrent NewConnection succeeded during shutdown")
		}
	}
	if err := service.Close(); err != nil {
		t.Fatalf("idempotent Service.Close error = %v", err)
	}
	for _, client := range clients {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatal("carrier peer remained open after shutdown")
		}
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(failure)
	}
}

func waitResult(t *testing.T, result <-chan error, failure string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal(failure)
		return nil
	}
}
