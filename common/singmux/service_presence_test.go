package singmux

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

func TestServicePresenceOwnsOnlyLiveSMUXDataStreams(t *testing.T) {
	dispatcher := newPresenceServiceDispatcher(false)
	carrier, closeCarrier := startPresenceSMUXService(t, dispatcher)
	defer closeCarrier()

	waitPresenceValue(t, &dispatcher.provider.snapshots, 1)
	if got := dispatcher.provider.subject.Load(); got == nil || *got != (session.PresenceSubject{
		Email: "alice@example.com", Level: 7, IP: netip.MustParseAddr("192.0.2.44"),
	}) {
		t.Fatalf("carrier subject = %+v", got)
	}
	assertPresenceValue(t, &dispatcher.tracker.active, 0)

	first := openPresenceSMUXStream(t, carrier)
	defer first.Close()
	assertPresenceDispatch(t, dispatcher, 1)
	second := openPresenceSMUXStream(t, carrier)
	defer second.Close()
	assertPresenceDispatch(t, dispatcher, 2)

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	waitPresenceValue(t, &dispatcher.tracker.active, 1)
	closeCarrier()
	waitPresenceValue(t, &dispatcher.tracker.active, 0)
}

func TestServicePresenceReleasesFailedSMUXDispatch(t *testing.T) {
	dispatcher := newPresenceServiceDispatcher(true)
	carrier, closeCarrier := startPresenceSMUXService(t, dispatcher)
	defer closeCarrier()
	stream := openPresenceSMUXStream(t, carrier)
	defer stream.Close()
	assertPresenceDispatch(t, dispatcher, 1)
	waitPresenceValue(t, &dispatcher.tracker.active, 0)
}

func TestServicePresenceSkipsSMUXControlStream(t *testing.T) {
	dispatcher := newPresenceServiceDispatcher(false)
	carrier, closeCarrier := startPresenceSMUXService(t, dispatcher)
	defer closeCarrier()
	stream, err := carrier.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := writeStreamRequest(stream, 0, X.TCPDestination(X.DomainAddress(brutalExchangeDomain), 1)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	waitPresenceValue(t, &dispatcher.provider.snapshots, 1)
	assertPresenceValue(t, &dispatcher.tracker.active, 0)
	select {
	case destination := <-dispatcher.dispatched:
		t.Fatalf("control stream reached dispatcher: %s", destination)
	default:
	}
}

func TestServicePresenceReleasesCanceledH2MUXStream(t *testing.T) {
	dispatcher := newPresenceServiceDispatcher(false)
	client, closeCarrier := startH2MuxServiceWithContext(t, NewService(dispatcher), []byte{0, 2}, func(net.Conn) context.Context {
		return presenceCarrierContext()
	})
	defer closeCarrier()
	response, bodyWriter := openH2MuxStream(t, client)
	if err := writeStreamRequest(bodyWriter, 0, X.TCPDestination(X.DomainAddress("example.com"), 443)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(response.Body); err != nil {
		t.Fatal(err)
	}
	assertPresenceDispatch(t, dispatcher, 1)
	if err := bodyWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	waitPresenceValue(t, &dispatcher.tracker.active, 0)
}

type presenceServiceDispatcher struct {
	tracker      *presenceServiceTracker
	provider     *presenceServiceProvider
	dispatched   chan X.Destination
	mode         chan session.PresenceMode
	atDispatch   chan int32
	failDispatch bool
}

func newPresenceServiceDispatcher(fail bool) *presenceServiceDispatcher {
	tracker := new(presenceServiceTracker)
	return &presenceServiceDispatcher{
		tracker:      tracker,
		provider:     &presenceServiceProvider{tracker: tracker},
		dispatched:   make(chan X.Destination, 4),
		mode:         make(chan session.PresenceMode, 4),
		atDispatch:   make(chan int32, 4),
		failDispatch: fail,
	}
}

func (d *presenceServiceDispatcher) PresenceProvider() session.PresenceProvider {
	return d.provider
}

func (*presenceServiceDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, io.ErrClosedPipe
}

func (d *presenceServiceDispatcher) DispatchLink(ctx context.Context, destination X.Destination, link *transport.Link) error {
	d.mode <- session.PresenceModeFromContext(ctx)
	d.atDispatch <- d.tracker.active.Load()
	d.dispatched <- destination
	if d.failDispatch {
		return errors.New("downstream rejected stream")
	}
	_, err := link.Reader.ReadMultiBuffer()
	return err
}

func (*presenceServiceDispatcher) Start() error      { return nil }
func (*presenceServiceDispatcher) Close() error      { return nil }
func (*presenceServiceDispatcher) Type() interface{} { return routing.DispatcherType() }

type presenceServiceProvider struct {
	tracker   *presenceServiceTracker
	snapshots atomic.Int32
	subject   atomic.Pointer[session.PresenceSubject]
}

func (p *presenceServiceProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil {
		p.snapshots.Add(1)
		return session.PresenceScope{}
	}
	subject := session.PresenceSubject{Email: inbound.User.Email, Level: inbound.User.Level, IP: inbound.PhysicalPeer}
	p.subject.Store(&subject)
	p.snapshots.Add(1)
	return session.NewPresenceScope(subject, p.tracker)
}

type presenceServiceTracker struct{ active atomic.Int32 }

func (t *presenceServiceTracker) Prepare(session.PresenceSubject) session.PresenceReservation {
	return &presenceServiceReservation{tracker: t}
}

type presenceServiceReservation struct {
	tracker *presenceServiceTracker
	once    sync.Once
}

func (r *presenceServiceReservation) Activate() session.PresenceLease {
	lease := &presenceServiceLease{tracker: r.tracker}
	r.once.Do(func() { r.tracker.active.Add(1) })
	return lease
}

func (r *presenceServiceReservation) Handoff(old session.PresenceLease) session.PresenceLease {
	if old != nil {
		old.Close()
	}
	return r.Activate()
}

func (r *presenceServiceReservation) HandoffAll(old []session.PresenceLease) []session.PresenceLease {
	for _, lease := range old {
		if lease != nil {
			lease.Close()
		}
	}
	return nil
}

func (*presenceServiceReservation) Abort() {}

type presenceServiceLease struct {
	tracker *presenceServiceTracker
	once    sync.Once
}

func (l *presenceServiceLease) Close() {
	l.once.Do(func() { l.tracker.active.Add(-1) })
}

func presenceCarrierContext() context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		PhysicalPeer: netip.MustParseAddr("192.0.2.44"),
		Tag:          "inbound-a",
		Name:         "vless",
		User:         &protocol.MemoryUser{Email: "alice@example.com", Level: 7},
	})
}

func startPresenceSMUXService(t *testing.T, dispatcher *presenceServiceDispatcher) (*localsmux.Session, func()) {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	ctx, cancel := context.WithCancel(presenceCarrierContext())
	result := make(chan error, 1)
	go func() { result <- NewService(dispatcher).NewConnection(ctx, serverConnection) }()
	if err := writeCarrierRequest(clientConnection, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	carrier, err := localsmux.Client(clientConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	return carrier, func() {
		once.Do(func() {
			_ = carrier.Close()
			cancel()
			_ = clientConnection.Close()
			select {
			case <-result:
			case <-time.After(time.Second):
				t.Error("SMUX presence service did not stop")
			}
		})
	}
}

func openPresenceSMUXStream(t *testing.T, carrier *localsmux.Session) net.Conn {
	t.Helper()
	stream, err := carrier.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStreamRequest(stream, 0, X.TCPDestination(X.DomainAddress("example.com"), 443)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	return stream
}

func assertPresenceDispatch(t *testing.T, dispatcher *presenceServiceDispatcher, wantActive int32) {
	t.Helper()
	select {
	case <-dispatcher.dispatched:
	case <-time.After(time.Second):
		t.Fatal("stream did not reach dispatcher")
	}
	select {
	case mode := <-dispatcher.mode:
		if mode != session.PresenceModeExternal {
			t.Fatalf("stream presence mode = %d, want External", mode)
		}
	case <-time.After(time.Second):
		t.Fatal("stream presence mode was not recorded")
	}
	select {
	case active := <-dispatcher.atDispatch:
		if active != wantActive {
			t.Fatalf("active leases at dispatch = %d, want %d", active, wantActive)
		}
	case <-time.After(time.Second):
		t.Fatal("active lease count was not recorded")
	}
}

func waitPresenceValue(t *testing.T, value *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if value.Load() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("value = %d, want %d", value.Load(), want)
}

func assertPresenceValue(t *testing.T, value *atomic.Int32, want int32) {
	t.Helper()
	if got := value.Load(); got != want {
		t.Fatalf("value = %d, want %d", got, want)
	}
}
