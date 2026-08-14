package mux

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestLegacyMuxPresenceOwnsOnlyPublishedDataSessions(t *testing.T) {
	for _, test := range []struct {
		name        string
		destination X.Destination
	}{
		{name: "TCP", destination: X.TCPDestination(X.DomainAddress("example.com"), 443)},
		{name: "packet UDP", destination: X.UDPDestination(X.DomainAddress("example.com"), 53)},
	} {
		t.Run(test.name, func(t *testing.T) {
			testLegacyMuxPresenceOwnsOnlyPublishedDataSession(t, test.destination)
		})
	}
}

func testLegacyMuxPresenceOwnsOnlyPublishedDataSession(t *testing.T, destination X.Destination) {
	dispatcher := newMuxPresenceDispatcher(false)
	serverLink, clientLink := muxPresenceLinkPair()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		PhysicalPeer: netip.MustParseAddr("192.0.2.44"),
		User:         &protocol.MemoryUser{Email: "alice@example.com", Level: 7},
	})
	server, err := NewServerWorker(ctx, dispatcher, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClientWorker(*clientLink, ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if dispatcher.provider.snapshots.Load() != 1 || dispatcher.tracker.active.Load() != 0 {
		t.Fatalf("idle carrier snapshots=%d active=%d", dispatcher.provider.snapshots.Load(), dispatcher.tracker.active.Load())
	}

	requestReader, requestWriter := pipe.New(pipe.WithoutSizeLimit())
	responseReader, responseWriter := pipe.New(pipe.WithoutSizeLimit())
	streamCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: destination,
	}})
	if !client.Dispatch(streamCtx, &transport.Link{Reader: requestReader, Writer: responseWriter}) {
		t.Fatal("client session was rejected")
	}
	if err := requestWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case mode := <-dispatcher.mode:
		if mode != session.PresenceModeExternal {
			t.Fatalf("server dispatch mode = %d, want External", mode)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not dispatch legacy Mux session")
	}
	waitMuxSessionState(t, server, &dispatcher.tracker.active, 1)
	common.Close(requestWriter)
	waitMuxSessionState(t, server, &dispatcher.tracker.active, 0)
	if server.Closed() {
		t.Fatal("session close terminated the live carrier")
	}
	common.Interrupt(responseReader)
}

func TestLegacyMuxPresenceDoesNotActivateFailedDispatch(t *testing.T) {
	dispatcher := newMuxPresenceDispatcher(true)
	serverLink, clientLink := muxPresenceLinkPair()
	server, err := NewServerWorker(session.ContextWithInbound(context.Background(), &session.Inbound{
		PhysicalPeer: netip.MustParseAddr("192.0.2.44"),
		User:         &protocol.MemoryUser{Email: "alice@example.com", Level: 7},
	}), dispatcher, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClientWorker(*clientLink, ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	requestReader, requestWriter := pipe.New(pipe.WithoutSizeLimit())
	_, responseWriter := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: X.TCPDestination(X.DomainAddress("example.com"), 443)}})
	if !client.Dispatch(ctx, &transport.Link{Reader: requestReader, Writer: responseWriter}) {
		t.Fatal("client session was rejected")
	}
	if err := requestWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatcher.mode:
	case <-time.After(time.Second):
		t.Fatal("failed dispatch was not attempted")
	}
	waitMuxPresence(t, &dispatcher.tracker.active, 0)
}

func TestLegacyMuxDuplicateSessionDoesNotDispatchOrReplaceOwner(t *testing.T) {
	dispatcher := newMuxPresenceDispatcher(false)
	serverLink, peerLink := muxPresenceLinkPair()
	server, err := NewServerWorker(session.ContextWithInbound(context.Background(), &session.Inbound{
		PhysicalPeer: netip.MustParseAddr("192.0.2.44"),
		User:         &protocol.MemoryUser{Email: "alice@example.com", Level: 7},
	}), dispatcher, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	first := NewWriter(7, destination, peerLink.Writer, protocol.TransferTypeStream, [8]byte{}, nil)
	if err := first.WriteMultiBuffer(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatcher.mode:
	case <-time.After(time.Second):
		t.Fatal("first session was not dispatched")
	}
	waitMuxPresence(t, &dispatcher.tracker.active, 1)
	second := NewWriter(7, destination, peerLink.Writer, protocol.TransferTypeStream, [8]byte{}, nil)
	if err := second.WriteMultiBuffer(nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	select {
	case <-dispatcher.mode:
		t.Fatal("duplicate session reached dispatcher")
	default:
	}
	if server.ActiveConnections() != 1 || dispatcher.tracker.active.Load() != 1 {
		t.Fatalf("duplicate changed owner: sessions=%d presence=%d", server.ActiveConnections(), dispatcher.tracker.active.Load())
	}
}

type muxPresenceDispatcher struct {
	provider *muxPresenceProvider
	tracker  *muxPresenceTracker
	mode     chan session.PresenceMode
	fail     bool
}

func newMuxPresenceDispatcher(fail bool) *muxPresenceDispatcher {
	tracker := new(muxPresenceTracker)
	return &muxPresenceDispatcher{provider: &muxPresenceProvider{tracker: tracker}, tracker: tracker, mode: make(chan session.PresenceMode, 4), fail: fail}
}

func (d *muxPresenceDispatcher) PresenceProvider() session.PresenceProvider { return d.provider }
func (d *muxPresenceDispatcher) Dispatch(ctx context.Context, _ X.Destination) (*transport.Link, error) {
	d.mode <- session.PresenceModeFromContext(ctx)
	if d.fail {
		return nil, errors.New("route rejected")
	}
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: reader, Writer: writer}, nil
}

func (*muxPresenceDispatcher) DispatchLink(context.Context, X.Destination, *transport.Link) error {
	return errors.New("unexpected DispatchLink")
}
func (*muxPresenceDispatcher) Start() error      { return nil }
func (*muxPresenceDispatcher) Close() error      { return nil }
func (*muxPresenceDispatcher) Type() interface{} { return routing.DispatcherType() }

type muxPresenceProvider struct {
	tracker   *muxPresenceTracker
	snapshots atomic.Int32
}

func (p *muxPresenceProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	p.snapshots.Add(1)
	inbound := session.InboundFromContext(ctx)
	return session.NewPresenceScope(session.PresenceSubject{Email: inbound.User.Email, Level: inbound.User.Level, IP: inbound.PhysicalPeer}, p.tracker)
}

type muxPresenceTracker struct{ active atomic.Int32 }

func (t *muxPresenceTracker) Prepare(session.PresenceSubject) session.PresenceReservation {
	return &muxPresenceReservation{tracker: t}
}

type muxPresenceReservation struct {
	tracker *muxPresenceTracker
	once    sync.Once
}

func (r *muxPresenceReservation) Activate() session.PresenceLease {
	lease := &muxPresenceLease{tracker: r.tracker}
	r.once.Do(func() { r.tracker.active.Add(1) })
	return lease
}

func (r *muxPresenceReservation) Handoff(old session.PresenceLease) session.PresenceLease {
	if old != nil {
		old.Close()
	}
	return r.Activate()
}

func (*muxPresenceReservation) HandoffAll([]session.PresenceLease) []session.PresenceLease {
	return nil
}
func (*muxPresenceReservation) Abort() {}

type muxPresenceLease struct {
	tracker *muxPresenceTracker
	once    sync.Once
}

func (l *muxPresenceLease) Close() { l.once.Do(func() { l.tracker.active.Add(-1) }) }

func muxPresenceLinkPair() (*transport.Link, *transport.Link) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
}

func waitMuxSessionState(t *testing.T, server *ServerWorker, active *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if active.Load() == want && server.ActiveConnections() == uint32(want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("session state: active sessions=%d presence=%d, want %d", server.ActiveConnections(), active.Load(), want)
}

func waitMuxPresence(t *testing.T, active *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if active.Load() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active presence = %d, want %d", active.Load(), want)
}
