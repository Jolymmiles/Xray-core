package mux

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestXUDPRuntimeAttachmentRebindAndCacheLifecycle(t *testing.T) {
	runtime := newRuntime()
	defer runtime.Close()
	tracker := newXUDPPresenceTracker()
	dispatcher := &xudpRuntimeDispatcher{
		provider: &xudpRuntimeProvider{tracker: tracker, principal: [32]byte{1, 2, 3}, reusable: true},
		modes:    make(chan session.PresenceMode, 4),
		backends: make(chan *transport.Link, 4),
	}
	firstWorker, firstPeer := startXUDPWorker(t, runtime, dispatcher, "192.0.2.10")
	defer firstWorker.Close()
	secondWorker, secondPeer := startXUDPWorker(t, runtime, dispatcher, "198.51.100.20")
	defer secondWorker.Close()
	target := X.UDPDestination(X.DomainAddress("example.com"), 53)
	globalID := [8]byte{9, 8, 7, 6}

	first := sendXUDPAttachment(t, firstPeer, 1, target, globalID, "first")
	backend := waitXUDPBackend(t, dispatcher)
	assertXUDPMode(t, dispatcher, session.PresenceModeUntracked)
	assertXUDPPayload(t, backend.Reader, "first")
	waitXUDPIPs(t, tracker, "192.0.2.10")

	second := sendXUDPAttachment(t, secondPeer, 2, target, globalID, "second")
	assertXUDPPayload(t, backend.Reader, "second")
	waitXUDPIPs(t, tracker, "198.51.100.20")
	reply := buf.FromBytes([]byte("reply"))
	reply.UDP = &target
	if err := backend.Writer.WriteMultiBuffer(buf.MultiBuffer{reply}); err != nil {
		t.Fatal(err)
	}
	assertXUDPResponse(t, secondPeer.Reader, 2, target, "reply")
	if firstWorker.ActiveConnections() != 0 || secondWorker.ActiveConnections() != 1 {
		t.Fatalf("rebind sessions first=%d second=%d", firstWorker.ActiveConnections(), secondWorker.ActiveConnections())
	}
	select {
	case <-dispatcher.backends:
		t.Fatal("rebind created a second backend")
	default:
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	waitXUDPIPs(t, tracker, "198.51.100.20")
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	waitXUDPIPs(t, tracker)
	if runtimeFlowCount(runtime) != 1 {
		t.Fatalf("detached cache flows = %d, want 1", runtimeFlowCount(runtime))
	}
	runtime.expire(time.Now().Add(2 * time.Minute))
	if runtimeFlowCount(runtime) != 0 {
		t.Fatalf("expired cache flows = %d, want 0", runtimeFlowCount(runtime))
	}
}

func TestXUDPRuntimeRejectsDestinationMismatchWithoutMovingPresence(t *testing.T) {
	runtime := newRuntime()
	defer runtime.Close()
	tracker := newXUDPPresenceTracker()
	dispatcher := &xudpRuntimeDispatcher{
		provider: &xudpRuntimeProvider{tracker: tracker, principal: [32]byte{4}, reusable: true},
		modes:    make(chan session.PresenceMode, 4),
		backends: make(chan *transport.Link, 4),
	}
	firstWorker, firstPeer := startXUDPWorker(t, runtime, dispatcher, "192.0.2.10")
	defer firstWorker.Close()
	secondWorker, secondPeer := startXUDPWorker(t, runtime, dispatcher, "198.51.100.20")
	defer secondWorker.Close()
	globalID := [8]byte{5, 4, 3}
	first := sendXUDPAttachment(t, firstPeer, 1, X.UDPDestination(X.DomainAddress("example.com"), 53), globalID, "first")
	defer first.Close()
	backend := waitXUDPBackend(t, dispatcher)
	assertXUDPPayload(t, backend.Reader, "first")
	waitXUDPIPs(t, tracker, "192.0.2.10")
	_ = sendXUDPAttachment(t, secondPeer, 2, X.UDPDestination(X.DomainAddress("other.example"), 53), globalID, "wrong")
	time.Sleep(20 * time.Millisecond)
	waitXUDPIPs(t, tracker, "192.0.2.10")
	if firstWorker.ActiveConnections() != 1 || secondWorker.ActiveConnections() != 0 {
		t.Fatalf("mismatch sessions first=%d second=%d", firstWorker.ActiveConnections(), secondWorker.ActiveConnections())
	}
}

func TestXUDPRuntimeIsolatesNonReusableWorkers(t *testing.T) {
	runtime := newRuntime()
	defer runtime.Close()
	tracker := newXUDPPresenceTracker()
	dispatcher := &xudpRuntimeDispatcher{
		provider: &xudpRuntimeProvider{tracker: tracker, reusable: false},
		modes:    make(chan session.PresenceMode, 4),
		backends: make(chan *transport.Link, 4),
	}
	firstWorker, firstPeer := startXUDPWorker(t, runtime, dispatcher, "192.0.2.10")
	defer firstWorker.Close()
	secondWorker, secondPeer := startXUDPWorker(t, runtime, dispatcher, "198.51.100.20")
	defer secondWorker.Close()
	target := X.UDPDestination(X.DomainAddress("example.com"), 53)
	globalID := [8]byte{1}
	first := sendXUDPAttachment(t, firstPeer, 1, target, globalID, "first")
	defer first.Close()
	second := sendXUDPAttachment(t, secondPeer, 2, target, globalID, "second")
	defer second.Close()
	firstBackend := waitXUDPBackend(t, dispatcher)
	secondBackend := waitXUDPBackend(t, dispatcher)
	got := map[string]bool{
		readXUDPPayload(t, firstBackend.Reader):  true,
		readXUDPPayload(t, secondBackend.Reader): true,
	}
	if !got["first"] || !got["second"] || len(got) != 2 {
		t.Fatalf("isolated backend payloads = %v", got)
	}
	waitXUDPIPs(t, tracker, "192.0.2.10", "198.51.100.20")
}

func TestXUDPRuntimeAllowsOnlyOneConcurrentRebind(t *testing.T) {
	runtime := newRuntime()
	defer runtime.Close()
	tracker := newXUDPPresenceTracker()
	tracker.handoffStarted = make(chan struct{})
	tracker.handoffRelease = make(chan struct{})
	dispatcher := &xudpRuntimeDispatcher{
		provider: &xudpRuntimeProvider{tracker: tracker, principal: [32]byte{8}, reusable: true},
		modes:    make(chan session.PresenceMode, 4),
		backends: make(chan *transport.Link, 4),
	}
	firstWorker, firstPeer := startXUDPWorker(t, runtime, dispatcher, "192.0.2.10")
	defer firstWorker.Close()
	winnerWorker, winnerPeer := startXUDPWorker(t, runtime, dispatcher, "198.51.100.20")
	defer winnerWorker.Close()
	loserWorker, loserPeer := startXUDPWorker(t, runtime, dispatcher, "203.0.113.30")
	defer loserWorker.Close()
	target := X.UDPDestination(X.DomainAddress("example.com"), 53)
	globalID := [8]byte{7}
	first := sendXUDPAttachment(t, firstPeer, 1, target, globalID, "first")
	defer first.Close()
	backend := waitXUDPBackend(t, dispatcher)
	assertXUDPPayload(t, backend.Reader, "first")
	winnerDone := make(chan *Writer, 1)
	go func() { winnerDone <- sendXUDPAttachment(t, winnerPeer, 2, target, globalID, "winner") }()
	select {
	case <-tracker.handoffStarted:
	case <-time.After(time.Second):
		t.Fatal("winner did not enter lease handoff")
	}
	_ = sendXUDPAttachment(t, loserPeer, 3, target, globalID, "loser")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !loserWorker.Closed() {
		time.Sleep(time.Millisecond)
	}
	if !loserWorker.Closed() {
		t.Fatal("losing concurrent rebind was not rejected before winner commit")
	}
	close(tracker.handoffRelease)
	winner := <-winnerDone
	defer winner.Close()
	assertXUDPPayload(t, backend.Reader, "winner")
	waitXUDPIPs(t, tracker, "198.51.100.20")
	if loserWorker.ActiveConnections() != 0 || runtimeFlowCount(runtime) != 1 {
		t.Fatalf("losing rebind sessions=%d flows=%d", loserWorker.ActiveConnections(), runtimeFlowCount(runtime))
	}
}

func TestXUDPRuntimePostCommitWriteFailureDoesNotPublishPresence(t *testing.T) {
	runtime := newRuntime()
	defer runtime.Close()
	tracker := newXUDPPresenceTracker()
	dispatcher := &xudpRuntimeDispatcher{
		provider: &xudpRuntimeProvider{tracker: tracker, principal: [32]byte{9}, reusable: true},
		modes:    make(chan session.PresenceMode, 4),
		backends: make(chan *transport.Link, 4),
		newBackend: func() (*transport.Link, *transport.Link) {
			reader := newBlockingXUDPReader()
			return &transport.Link{Reader: reader, Writer: errorXUDPWriter{}}, &transport.Link{Reader: reader, Writer: errorXUDPWriter{}}
		},
	}
	worker, peer := startXUDPWorker(t, runtime, dispatcher, "192.0.2.10")
	defer worker.Close()
	_ = sendXUDPAttachment(t, peer, 1, X.UDPDestination(X.DomainAddress("example.com"), 53), [8]byte{6}, "fails")
	waitXUDPIPs(t, tracker)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && runtimeFlowCount(runtime) != 0 {
		time.Sleep(time.Millisecond)
	}
	if runtimeFlowCount(runtime) != 0 || worker.ActiveConnections() != 0 {
		t.Fatalf("post-commit failure left flows=%d sessions=%d", runtimeFlowCount(runtime), worker.ActiveConnections())
	}
}

func TestXUDPRuntimeCloseDrainsActiveAttachmentAndBackend(t *testing.T) {
	runtime := newRuntime()
	tracker := newXUDPPresenceTracker()
	dispatcher := &xudpRuntimeDispatcher{
		provider: &xudpRuntimeProvider{tracker: tracker, principal: [32]byte{10}, reusable: true},
		modes:    make(chan session.PresenceMode, 4),
		backends: make(chan *transport.Link, 4),
	}
	worker, peer := startXUDPWorker(t, runtime, dispatcher, "192.0.2.10")
	defer worker.Close()
	_ = sendXUDPAttachment(t, peer, 1, X.UDPDestination(X.DomainAddress("example.com"), 53), [8]byte{11}, "active")
	backend := waitXUDPBackend(t, dispatcher)
	assertXUDPPayload(t, backend.Reader, "active")
	waitXUDPIPs(t, tracker, "192.0.2.10")
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	waitXUDPIPs(t, tracker)
	if runtimeFlowCount(runtime) != 0 || worker.ActiveConnections() != 0 {
		t.Fatalf("runtime close left flows=%d sessions=%d", runtimeFlowCount(runtime), worker.ActiveConnections())
	}
}

func TestXUDPRuntimeCloseWaitsForAuthorizedRebindPublication(t *testing.T) {
	runtime := newRuntime()
	tracker := newXUDPPresenceTracker()
	tracker.handoffStarted = make(chan struct{})
	tracker.handoffRelease = make(chan struct{})
	backendReader, backendWriter := pipe.New(pipe.WithoutSizeLimit())
	key := xudpRuntimeKey{principal: [32]byte{21}, globalID: [8]byte{22}}
	flow := newXUDPFlow(runtime, key, X.UDPDestination(X.DomainAddress("example.com"), 53), &transport.Link{Reader: backendReader, Writer: backendWriter})
	runtime.mu.Lock()
	runtime.flows[key] = flow
	runtime.mu.Unlock()
	registry := newSessionRegistry()
	sink := runtime.newResponseSink(buf.Discard)
	firstScope := session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.10")}, tracker)
	first, err := flow.attach(registry.reserve(1), firstScope, sink)
	if err != nil {
		t.Fatal(err)
	}

	secondScope := session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("198.51.100.20")}, tracker)
	_, finishTransaction, ok := runtime.beginTransaction(context.Background())
	if !ok {
		t.Fatal("runtime rejected rebind transaction")
	}
	attachDone := make(chan error, 1)
	go func() {
		defer finishTransaction()
		_, err := flow.attach(registry.reserve(2), secondScope, sink)
		attachDone <- err
	}()
	select {
	case <-tracker.handoffStarted:
	case <-time.After(time.Second):
		t.Fatal("rebind did not reach authorized handoff")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("runtime close returned before authorized publication: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(tracker.handoffRelease)
	if err := <-attachDone; err != nil {
		t.Fatalf("authorized rebind failed instead of publishing: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	_ = first.Close(false)
	waitXUDPIPs(t, tracker)
	if registry.activeCount() != 0 {
		t.Fatalf("runtime close left %d active sessions", registry.activeCount())
	}
}

func TestXUDPRuntimeCloseCancelsBlockedBackendDispatch(t *testing.T) {
	runtime := newRuntime()
	txCtx, finishTransaction, ok := runtime.beginTransaction(context.Background())
	if !ok {
		t.Fatal("runtime rejected backend dispatch transaction")
	}
	dispatcher := &blockingXUDPDispatcher{started: make(chan struct{})}
	dispatchDone := make(chan error, 1)
	go func() {
		defer finishTransaction()
		_, err := runtime.xudpFlow(txCtx, xudpRuntimeKey{globalID: [8]byte{45}}, X.UDPDestination(X.DomainAddress("example.com"), 53), dispatcher)
		dispatchDone <- err
	}()
	<-dispatcher.started

	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case err := <-dispatchDone:
		if err == nil {
			t.Fatal("blocked backend dispatch succeeded during runtime close")
		}
	case <-time.After(100 * time.Millisecond):
		dispatcher.release()
		<-dispatchDone
		<-closeDone
		t.Fatal("runtime close did not cancel blocked backend dispatch")
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

type blockingXUDPDispatcher struct {
	started        chan struct{}
	once           sync.Once
	releaseChannel chan struct{}
}

func (d *blockingXUDPDispatcher) Dispatch(ctx context.Context, _ X.Destination) (*transport.Link, error) {
	d.once.Do(func() {
		d.releaseChannel = make(chan struct{})
		close(d.started)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.releaseChannel:
		return nil, io.ErrClosedPipe
	}
}
func (d *blockingXUDPDispatcher) release() { close(d.releaseChannel) }
func (*blockingXUDPDispatcher) DispatchLink(context.Context, X.Destination, *transport.Link) error {
	return io.ErrClosedPipe
}
func (*blockingXUDPDispatcher) Start() error      { return nil }
func (*blockingXUDPDispatcher) Close() error      { return nil }
func (*blockingXUDPDispatcher) Type() interface{} { return routing.DispatcherType() }

func TestXUDPBackendContextOutlivesAttachmentPublication(t *testing.T) {
	runtime := newRuntime()
	tracker := newXUDPPresenceTracker()
	contextObserved := make(chan context.Context, 1)
	dispatcher := &xudpRuntimeDispatcher{
		provider:        &xudpRuntimeProvider{tracker: tracker, principal: [32]byte{43}, reusable: true},
		modes:           make(chan session.PresenceMode, 4),
		backends:        make(chan *transport.Link, 4),
		contextObserved: contextObserved,
	}
	worker, peer := startXUDPWorker(t, runtime, dispatcher, "192.0.2.10")
	defer worker.Close()
	_ = sendXUDPAttachment(t, peer, 1, X.UDPDestination(X.DomainAddress("example.com"), 53), [8]byte{44}, "active")
	backend := waitXUDPBackend(t, dispatcher)
	assertXUDPPayload(t, backend.Reader, "active")
	backendCtx := <-contextObserved
	select {
	case <-backendCtx.Done():
		t.Fatal("attachment publication canceled the live XUDP backend context")
	default:
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backendCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("runtime close did not cancel the XUDP backend context")
	}
}

func TestXUDPRuntimeCloseUnblocksPostCommitInitialWrite(t *testing.T) {
	runtime := newRuntime()
	tracker := newXUDPPresenceTracker()
	backendReader := newBlockingXUDPReader()
	backendWriter := &blockingRuntimeWriter{started: make(chan struct{}), closed: make(chan struct{})}
	dispatcher := &xudpRuntimeDispatcher{
		provider: &xudpRuntimeProvider{tracker: tracker, principal: [32]byte{41}, reusable: true},
		modes:    make(chan session.PresenceMode, 4),
		backends: make(chan *transport.Link, 4),
		newBackend: func() (*transport.Link, *transport.Link) {
			server := &transport.Link{Reader: backendReader, Writer: backendWriter}
			peer := &transport.Link{Reader: backendReader, Writer: backendWriter}
			return server, peer
		},
	}
	worker, peer := startXUDPWorker(t, runtime, dispatcher, "192.0.2.10")
	defer worker.Close()
	_ = sendXUDPAttachment(t, peer, 1, X.UDPDestination(X.DomainAddress("example.com"), 53), [8]byte{42}, "blocked")
	select {
	case <-backendWriter.started:
	case <-time.After(time.Second):
		t.Fatal("initial XUDP write did not block")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		_ = backendWriter.Close()
		<-closeDone
		t.Fatal("runtime close waited for post-commit initial write before closing its backend")
	}
}

func TestXUDPFlowCloseCompletesAuthorizedAttachmentCommit(t *testing.T) {
	runtime := newRuntime()
	tracker := newXUDPPresenceTracker()
	tracker.handoffStarted = make(chan struct{})
	tracker.handoffRelease = make(chan struct{})
	backendReader, backendWriter := pipe.New(pipe.WithoutSizeLimit())
	key := xudpRuntimeKey{principal: [32]byte{31}, globalID: [8]byte{32}}
	flow := newXUDPFlow(runtime, key, X.UDPDestination(X.DomainAddress("example.com"), 53), &transport.Link{Reader: backendReader, Writer: backendWriter})
	runtime.mu.Lock()
	runtime.flows[key] = flow
	runtime.mu.Unlock()
	registry := newSessionRegistry()
	sink := runtime.newResponseSink(buf.Discard)
	firstScope := session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.10")}, tracker)
	if _, err := flow.attach(registry.reserve(1), firstScope, sink); err != nil {
		t.Fatal(err)
	}

	secondScope := session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("198.51.100.20")}, tracker)
	attachDone := make(chan error, 1)
	go func() {
		_, err := flow.attach(registry.reserve(2), secondScope, sink)
		attachDone <- err
	}()
	select {
	case <-tracker.handoffStarted:
	case <-time.After(time.Second):
		t.Fatal("rebind did not reach authorized handoff")
	}
	flow.close()
	close(tracker.handoffRelease)
	if err := <-attachDone; err == nil {
		t.Fatal("attachment succeeded after flow close")
	}

	closeDone := make(chan struct{})
	go func() {
		registry.close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("registry close blocked on an authorized attachment commit")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestXUDPRuntimeThousandRebindsEndAtZero(t *testing.T) {
	runtime := newRuntime()
	defer runtime.Close()
	tracker := newXUDPPresenceTracker()
	backendReader, backendWriter := pipe.New(pipe.WithoutSizeLimit())
	key := xudpRuntimeKey{principal: [32]byte{12}, globalID: [8]byte{13}}
	flow := newXUDPFlow(runtime, key, X.UDPDestination(X.DomainAddress("example.com"), 53), &transport.Link{Reader: backendReader, Writer: backendWriter})
	runtime.mu.Lock()
	runtime.flows[key] = flow
	runtime.mu.Unlock()
	registry := newSessionRegistry()
	sink := runtime.newResponseSink(buf.Discard)
	var owner *Session
	for index := range 1000 {
		ip := netip.MustParseAddr("192.0.2.10")
		if index%2 != 0 {
			ip = netip.MustParseAddr("198.51.100.20")
		}
		scope := session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: ip}, tracker)
		admission := registry.reserve(uint16(index + 1))
		var err error
		owner, err = flow.attach(admission, scope, sink)
		if err != nil {
			t.Fatalf("rebind %d: %v", index, err)
		}
	}
	if owner == nil {
		t.Fatal("no final attachment")
	}
	_ = owner.Close(false)
	waitXUDPIPs(t, tracker)
	if registry.activeCount() != 0 {
		t.Fatalf("1000 rebinds left %d active sessions", registry.activeCount())
	}
}

type xudpRuntimeDispatcher struct {
	provider        *xudpRuntimeProvider
	modes           chan session.PresenceMode
	backends        chan *transport.Link
	dispatches      atomic.Int32
	newBackend      func() (*transport.Link, *transport.Link)
	contextObserved chan context.Context
}

func (d *xudpRuntimeDispatcher) PresenceProvider() session.PresenceProvider { return d.provider }
func (d *xudpRuntimeDispatcher) Dispatch(ctx context.Context, _ X.Destination) (*transport.Link, error) {
	d.dispatches.Add(1)
	d.modes <- session.PresenceModeFromContext(ctx)
	if d.contextObserved != nil {
		d.contextObserved <- ctx
	}
	server, peer := muxPresenceLinkPair()
	if d.newBackend != nil {
		server, peer = d.newBackend()
	}
	d.backends <- peer
	return server, nil
}

func (*xudpRuntimeDispatcher) DispatchLink(context.Context, X.Destination, *transport.Link) error {
	return errors.New("unexpected DispatchLink")
}
func (*xudpRuntimeDispatcher) Start() error      { return nil }
func (*xudpRuntimeDispatcher) Close() error      { return nil }
func (*xudpRuntimeDispatcher) Type() interface{} { return routing.DispatcherType() }

type xudpRuntimeProvider struct {
	tracker   *xudpPresenceTracker
	principal [32]byte
	reusable  bool
}

func (p *xudpRuntimeProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	inbound := session.InboundFromContext(ctx)
	return session.NewPresenceScope(session.PresenceSubject{
		Email: inbound.User.Email, Level: inbound.User.Level, IP: inbound.PhysicalPeer,
		PrincipalKey: p.principal, Reusable: p.reusable,
	}, p.tracker)
}

type xudpPresenceTracker struct {
	mu             sync.Mutex
	next           uint64
	active         map[uint64]netip.Addr
	handoffStarted chan struct{}
	handoffRelease chan struct{}
	handoffOnce    sync.Once
}

func newXUDPPresenceTracker() *xudpPresenceTracker {
	return &xudpPresenceTracker{active: make(map[uint64]netip.Addr)}
}

func (t *xudpPresenceTracker) Prepare(subject session.PresenceSubject) session.PresenceReservation {
	return &xudpPresenceReservation{tracker: t, ip: subject.IP}
}

type xudpPresenceReservation struct {
	tracker *xudpPresenceTracker
	ip      netip.Addr
	once    sync.Once
	lease   session.PresenceLease
}

func (r *xudpPresenceReservation) Activate() session.PresenceLease {
	r.once.Do(func() {
		r.tracker.mu.Lock()
		r.tracker.next++
		token := r.tracker.next
		r.tracker.active[token] = r.ip
		r.tracker.mu.Unlock()
		r.lease = &xudpPresenceLease{tracker: r.tracker, token: token}
	})
	return r.lease
}

func (r *xudpPresenceReservation) Handoff(old session.PresenceLease) session.PresenceLease {
	if r.tracker.handoffStarted != nil {
		r.tracker.handoffOnce.Do(func() { close(r.tracker.handoffStarted) })
		<-r.tracker.handoffRelease
	}
	lease := r.Activate()
	if old != nil {
		old.Close()
	}
	return lease
}

func (*xudpPresenceReservation) HandoffAll([]session.PresenceLease) []session.PresenceLease {
	return nil
}
func (*xudpPresenceReservation) Abort() {}

type xudpPresenceLease struct {
	tracker *xudpPresenceTracker
	token   uint64
	once    sync.Once
}

func (l *xudpPresenceLease) Close() {
	l.once.Do(func() {
		l.tracker.mu.Lock()
		delete(l.tracker.active, l.token)
		l.tracker.mu.Unlock()
	})
}

func startXUDPWorker(t *testing.T, runtime *Runtime, dispatcher *xudpRuntimeDispatcher, ip string) (*ServerWorker, *transport.Link) {
	t.Helper()
	server, peer := muxPresenceLinkPair()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		PhysicalPeer: netip.MustParseAddr(ip),
		User:         &protocol.MemoryUser{Email: "alice@example.com", Level: 7},
	})
	worker, err := newServerWorker(ctx, dispatcher, server, runtime, false)
	if err != nil {
		t.Fatal(err)
	}
	return worker, peer
}

func sendXUDPAttachment(t *testing.T, peer *transport.Link, id uint16, target X.Destination, globalID [8]byte, payload string) *Writer {
	t.Helper()
	writer := NewWriter(id, target, peer.Writer, protocol.TransferTypePacket, globalID, nil)
	buffer := buf.FromBytes([]byte(payload))
	buffer.UDP = &target
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
		t.Fatal(err)
	}
	return writer
}

func waitXUDPBackend(t *testing.T, dispatcher *xudpRuntimeDispatcher) *transport.Link {
	t.Helper()
	select {
	case backend := <-dispatcher.backends:
		return backend
	case <-time.After(time.Second):
		t.Fatal("XUDP backend was not dispatched")
		return nil
	}
}

func assertXUDPMode(t *testing.T, dispatcher *xudpRuntimeDispatcher, want session.PresenceMode) {
	t.Helper()
	select {
	case got := <-dispatcher.modes:
		if got != want {
			t.Fatalf("backend presence mode = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("XUDP backend mode was not recorded")
	}
}

func assertXUDPPayload(t *testing.T, reader buf.Reader, want string) {
	t.Helper()
	if got := readXUDPPayload(t, reader); got != want {
		t.Fatalf("backend payload = %q, want %q", got, want)
	}
}

func assertXUDPResponse(t *testing.T, reader buf.Reader, id uint16, target X.Destination, want string) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		buffered := &buf.BufferedReader{Reader: reader}
		var metadata FrameMetadata
		if err := metadata.Unmarshal(buffered, false); err != nil {
			result <- err
			return
		}
		if metadata.SessionID != id || metadata.SessionStatus != SessionStatusKeep || !metadata.Option.Has(OptionData) {
			result <- errors.New("unexpected XUDP response metadata")
			return
		}
		payload, err := NewPacketReader(buffered, &target).ReadMultiBuffer()
		if err == nil {
			defer buf.ReleaseMulti(payload)
			if payload.String() != want {
				err = errors.New("unexpected XUDP response payload")
			}
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out reading XUDP attachment response")
	}
}

func readXUDPPayload(t *testing.T, reader buf.Reader) string {
	t.Helper()
	result := make(chan struct {
		payload buf.MultiBuffer
		err     error
	}, 1)
	go func() {
		payload, err := reader.ReadMultiBuffer()
		result <- struct {
			payload buf.MultiBuffer
			err     error
		}{payload, err}
	}()
	select {
	case got := <-result:
		if got.err != nil && !errors.Is(got.err, io.EOF) {
			t.Fatal(got.err)
		}
		defer buf.ReleaseMulti(got.payload)
		return got.payload.String()
	case <-time.After(time.Second):
		t.Fatal("timed out reading XUDP backend payload")
		return ""
	}
}

func waitXUDPIPs(t *testing.T, tracker *xudpPresenceTracker, want ...string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		tracker.mu.Lock()
		got := make(map[string]struct{}, len(tracker.active))
		for _, ip := range tracker.active {
			got[ip.String()] = struct{}{}
		}
		tracker.mu.Unlock()
		if len(got) == len(want) {
			matched := true
			for _, ip := range want {
				_, matched = got[ip]
				if !matched {
					break
				}
			}
			if matched {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	t.Fatalf("active IPs = %v, want %v", tracker.active, want)
}

func runtimeFlowCount(runtime *Runtime) int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return len(runtime.flows)
}

type errorXUDPWriter struct{}

func (errorXUDPWriter) WriteMultiBuffer(payload buf.MultiBuffer) error {
	buf.ReleaseMulti(payload)
	return io.ErrClosedPipe
}

type blockingXUDPReader struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingXUDPReader() *blockingXUDPReader {
	return &blockingXUDPReader{closed: make(chan struct{})}
}

func (r *blockingXUDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.closed
	return nil, io.ErrClosedPipe
}

func (r *blockingXUDPReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}
