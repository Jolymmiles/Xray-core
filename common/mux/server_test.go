package mux_test

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	statscommand "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type muxPresenceTracker struct {
	active atomic.Int32
	online featurestats.OnlineMap
}

func (t *muxPresenceTracker) Prepare(subject session.PresenceSubject) session.PresenceReservation {
	return &muxPresenceReservation{tracker: t, ip: muxPresenceIP(subject.IP)}
}

type muxPresenceReservation struct {
	tracker *muxPresenceTracker
	ip      string
	once    sync.Once
}

func (r *muxPresenceReservation) Activate() session.PresenceLease {
	r.tracker.active.Add(1)
	if r.tracker.online != nil {
		r.tracker.online.AddIP(r.ip)
	}
	return &muxPresenceLease{tracker: r.tracker, ip: r.ip}
}

func (r *muxPresenceReservation) Handoff(previous session.PresenceLease) session.PresenceLease {
	if previous != nil {
		previous.Close()
	}
	return r.Activate()
}

func (r *muxPresenceReservation) Abort() {}

type muxPresenceLease struct {
	tracker *muxPresenceTracker
	ip      string
	once    sync.Once
}

func (l *muxPresenceLease) Close() {
	l.once.Do(func() {
		l.tracker.active.Add(-1)
		if l.tracker.online != nil {
			l.tracker.online.RemoveIP(l.ip)
		}
	})
}

func muxPresenceIP(ip netip.Addr) string {
	if ip.Is6() {
		return "[" + ip.String() + "]"
	}
	return ip.String()
}

func newRPCPresenceTracker(t *testing.T) (*muxPresenceTracker, statscommand.StatsServiceServer, string) {
	t.Helper()
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	name := "user>>>user@example.com>>>online"
	online, err := manager.GetOrRegisterOnlineMap(name)
	if err != nil {
		t.Fatal(err)
	}
	return &muxPresenceTracker{online: online}, statscommand.NewStatsServer(manager), name
}

func assertRPCOnline(t *testing.T, server statscommand.StatsServiceServer, name string, want int64) {
	t.Helper()
	response, err := server.GetStatsOnline(context.Background(), &statscommand.GetStatsRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Stat.Value; got != want {
		t.Fatalf("StatsService online value = %d; want %d", got, want)
	}
}

type muxPresenceProvider struct {
	tracker *muxPresenceTracker
	subject session.PresenceSubject
}

func (p muxPresenceProvider) SnapshotPresence(context.Context) session.PresenceScope {
	subject := p.subject
	if !subject.Valid() {
		subject = session.PresenceSubject{
			Email:        "user@example.com",
			IP:           netip.MustParseAddr("192.0.2.1"),
			PrincipalKey: [32]byte{1},
			Reusable:     true,
		}
	}
	return session.PresenceScope{
		Subject: subject,
		Tracker: p.tracker,
	}
}

func TestXUDPRebindReusesBackendAndTransfersAttachmentPresence(t *testing.T) {
	websiteUplink, websiteDownlink := newLinkPair()
	var dispatches atomic.Int32
	dispatcher := TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		dispatches.Add(1)
		return websiteDownlink, nil
	}}
	tracker, statsServer, statsName := newRPCPresenceTracker(t)
	runtime := mux.NewRuntime()
	t.Cleanup(func() { _ = runtime.Close() })
	principal := [32]byte{9}

	newCarrier := func(ip string) (*mux.ServerWorker, *mux.ClientWorker, *transport.Link) {
		serverLink, clientLink := newLinkPair()
		server, err := mux.NewServerWorkerWithOptions(context.Background(), &dispatcher, serverLink, mux.ServerWorkerOptions{
			Runtime: runtime,
			PresenceProvider: muxPresenceProvider{tracker: tracker, subject: session.PresenceSubject{
				Email: "user@example.com", IP: netip.MustParseAddr(ip), PrincipalKey: principal, Reusable: true,
			}},
			PresenceMode: session.PresenceModeStructural,
		})
		if err != nil {
			t.Fatal(err)
		}
		client, err := mux.NewClientWorker(*clientLink, mux.ClientStrategy{})
		if err != nil {
			t.Fatal(err)
		}
		clientUplink, clientDownlink := newLinkPair()
		target := net.UDPDestination(net.DomainAddress("dns.example"), 53)
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
		ctx = session.ContextWithInbound(ctx, &session.Inbound{
			Source: net.UDPDestination(net.ParseAddress("10.0.0.1"), 12345),
			Name:   "socks",
		})
		ctx = context.WithValue(ctx, "cone", true)
		if !client.Dispatch(ctx, clientUplink) {
			t.Fatal("XUDP client dispatch failed")
		}
		return server, client, clientDownlink
	}

	firstServer, firstClient, firstInput := newCarrier("192.0.2.1")
	firstPayload := buf.FromBytes([]byte("first"))
	firstTarget := net.UDPDestination(net.DomainAddress("dns.example"), 53)
	firstPayload.UDP = &firstTarget
	if err := firstInput.Writer.WriteMultiBuffer(buf.MultiBuffer{firstPayload}); err != nil {
		t.Fatal(err)
	}
	if _, err := websiteUplink.Reader.ReadMultiBuffer(); err != nil {
		t.Fatal(err)
	}
	if dispatches.Load() != 1 || tracker.active.Load() != 1 {
		t.Fatalf("after first attach dispatches/leases = %d/%d; want 1/1", dispatches.Load(), tracker.active.Load())
	}
	assertRPCOnline(t, statsServer, statsName, 1)

	secondServer, secondClient, secondInput := newCarrier("198.51.100.2")
	secondPayload := buf.FromBytes([]byte("second"))
	secondPayload.UDP = &firstTarget
	if err := secondInput.Writer.WriteMultiBuffer(buf.MultiBuffer{secondPayload}); err != nil {
		t.Fatal(err)
	}
	if _, err := websiteUplink.Reader.ReadMultiBuffer(); err != nil {
		t.Fatal(err)
	}
	if dispatches.Load() != 1 || tracker.active.Load() != 1 {
		t.Fatalf("after rebind dispatches/leases = %d/%d; want 1/1", dispatches.Load(), tracker.active.Load())
	}
	assertRPCOnline(t, statsServer, statsName, 1)

	_ = firstClient.Close()
	_ = secondClient.Close()
	_ = runtime.Close()
	<-firstServer.WaitClosed()
	<-secondServer.WaitClosed()
	if tracker.active.Load() != 0 {
		t.Fatalf("leases after runtime close = %d; want 0", tracker.active.Load())
	}
	assertRPCOnline(t, statsServer, statsName, 0)
}

type failSecondXUDPWrite struct {
	writes atomic.Int32
	events chan int32
}

func (w *failSecondXUDPWrite) WriteMultiBuffer(payload buf.MultiBuffer) error {
	buf.ReleaseMulti(payload)
	count := w.writes.Add(1)
	w.events <- count
	if count == 2 {
		return io.ErrClosedPipe
	}
	return nil
}

func TestXUDPPostcommitFirstWriteFailureDoesNotRestoreOldAttachment(t *testing.T) {
	backendReader, _ := pipe.New(pipe.WithoutSizeLimit())
	backendWriter := &failSecondXUDPWrite{events: make(chan int32, 2)}
	dispatcher := TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return &transport.Link{Reader: backendReader, Writer: backendWriter}, nil
	}}
	tracker, statsServer, statsName := newRPCPresenceTracker(t)
	runtime := mux.NewRuntime()
	t.Cleanup(func() { _ = runtime.Close() })
	principal := [32]byte{10}
	target := net.UDPDestination(net.DomainAddress("dns.example"), 53)

	newCarrier := func(ip string) (*mux.ServerWorker, *mux.ClientWorker, *transport.Link) {
		serverLink, clientLink := newLinkPair()
		server, err := mux.NewServerWorkerWithOptions(context.Background(), &dispatcher, serverLink, mux.ServerWorkerOptions{
			Runtime: runtime,
			PresenceProvider: muxPresenceProvider{tracker: tracker, subject: session.PresenceSubject{
				Email: "user@example.com", IP: netip.MustParseAddr(ip), PrincipalKey: principal, Reusable: true,
			}},
			PresenceMode: session.PresenceModeStructural,
		})
		if err != nil {
			t.Fatal(err)
		}
		client, err := mux.NewClientWorker(*clientLink, mux.ClientStrategy{})
		if err != nil {
			t.Fatal(err)
		}
		uplink, downlink := newLinkPair()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
		ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: net.UDPDestination(net.ParseAddress("10.0.0.1"), 12345)})
		ctx = context.WithValue(ctx, "cone", true)
		if !client.Dispatch(ctx, uplink) {
			t.Fatal("XUDP client dispatch failed")
		}
		return server, client, downlink
	}

	firstServer, firstClient, firstInput := newCarrier("192.0.2.1")
	firstPayload := buf.FromBytes([]byte("first"))
	firstPayload.UDP = &target
	if err := firstInput.Writer.WriteMultiBuffer(buf.MultiBuffer{firstPayload}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backendWriter.events:
	case <-time.After(time.Second):
		t.Fatal("initial XUDP payload did not reach backend")
	}
	assertRPCOnline(t, statsServer, statsName, 1)

	secondServer, secondClient, secondInput := newCarrier("198.51.100.2")
	secondPayload := buf.FromBytes([]byte("second"))
	secondPayload.UDP = &target
	if err := secondInput.Writer.WriteMultiBuffer(buf.MultiBuffer{secondPayload}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backendWriter.events:
	case <-time.After(time.Second):
		t.Fatal("committed rebind payload did not reach backend")
	}
	deadline := time.Now().Add(time.Second)
	for tracker.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := tracker.active.Load(); got != 0 {
		t.Fatalf("postcommit failure restored or retained %d attachment leases", got)
	}
	assertRPCOnline(t, statsServer, statsName, 0)

	_ = firstClient.Close()
	_ = secondClient.Close()
	_ = runtime.Close()
	<-firstServer.WaitClosed()
	<-secondServer.WaitClosed()
}

func newLinkPair() (*transport.Link, *transport.Link) {
	opt := pipe.WithoutSizeLimit()
	uplinkReader, uplinkWriter := pipe.New(opt)
	downlinkReader, downlinkWriter := pipe.New(opt)

	uplink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	downlink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	return uplink, downlink
}

type TestDispatcher struct {
	OnDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *TestDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.OnDispatch(ctx, dest)
}

func (d *TestDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	return nil
}

func (d *TestDispatcher) Start() error {
	return nil
}

func (d *TestDispatcher) Close() error {
	return nil
}

func (*TestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestRegressionOutboundLeak(t *testing.T) {
	originalOutbounds := []*session.Outbound{{}}
	serverCtx := session.ContextWithOutbounds(context.Background(), originalOutbounds)

	websiteUplink, websiteDownlink := newLinkPair()

	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			// emulate what DefaultRouter.Dispatch does, and mutate something on the context
			ob := session.OutboundsFromContext(ctx)[0]
			ob.Target = dest
			return websiteDownlink, nil
		},
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	_, err := mux.NewServerWorker(serverCtx, &dispatcher, muxServerUplink)
	common.Must(err)

	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	common.Must(err)

	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})

	muxClientUplink, muxClientDownlink := newLinkPair()

	ok := client.Dispatch(clientCtx, muxClientUplink)
	if !ok {
		t.Error("failed to dispatch")
	}

	{
		b := buf.FromBytes([]byte("hello"))
		common.Must(muxClientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err := websiteUplink.Reader.ReadMultiBuffer()
	common.Must(err)
	res := resMb.String()
	if res != "hello" {
		t.Error("upload: ", res)
	}

	{
		b := buf.FromBytes([]byte("world"))
		common.Must(websiteUplink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err = muxClientDownlink.Reader.ReadMultiBuffer()
	common.Must(err)
	res = resMb.String()
	if res != "world" {
		t.Error("download: ", res)
	}

	outbounds := session.OutboundsFromContext(serverCtx)
	if outbounds[0] != originalOutbounds[0] {
		t.Error("outbound got reassigned: ", outbounds[0])
	}

	if outbounds[0].Target.Address != nil {
		t.Error("outbound target got leaked: ", outbounds[0].Target.String())
	}
}

func TestStructuralPresenceTracksLogicalSessionNotCarrier(t *testing.T) {
	websiteUplink, websiteDownlink := newLinkPair()
	dispatcher := TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return websiteDownlink, nil
	}}
	tracker, statsServer, statsName := newRPCPresenceTracker(t)
	muxServerUplink, muxServerDownlink := newLinkPair()
	server, err := mux.NewServerWorkerWithOptions(context.Background(), &dispatcher, muxServerUplink, mux.ServerWorkerOptions{
		PresenceProvider: muxPresenceProvider{tracker: tracker},
		PresenceMode:     session.PresenceModeStructural,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := tracker.active.Load(); got != 0 {
		t.Fatalf("idle carrier active leases = %d; want 0", got)
	}
	assertRPCOnline(t, statsServer, statsName, 0)

	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	clientUplink, clientDownlink := newLinkPair()
	if !client.Dispatch(clientCtx, clientUplink) {
		t.Fatal("client dispatch failed")
	}
	if err := clientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := websiteUplink.Reader.ReadMultiBuffer(); err != nil {
		t.Fatal(err)
	}
	if got := tracker.active.Load(); got != 1 {
		t.Fatalf("active logical session leases = %d; want 1", got)
	}
	assertRPCOnline(t, statsServer, statsName, 1)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	<-server.WaitClosed()
	if got := tracker.active.Load(); got != 0 {
		t.Fatalf("leases after logical session close = %d; want 0", got)
	}
	assertRPCOnline(t, statsServer, statsName, 0)
}
