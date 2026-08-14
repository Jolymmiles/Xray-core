package inbound

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"sync"
	"testing"
	"time"

	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
)

type vlessReverseOutboundManager struct {
	mu       sync.Mutex
	handlers map[string]outbound.Handler
	ready    bool
	listed   chan struct{}
}

func (*vlessReverseOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (*vlessReverseOutboundManager) Start() error      { return nil }
func (*vlessReverseOutboundManager) Close() error      { return nil }
func (m *vlessReverseOutboundManager) GetHandler(tag string) outbound.Handler {
	return m.handlers[tag]
}
func (*vlessReverseOutboundManager) GetDefaultHandler() outbound.Handler { return nil }
func (m *vlessReverseOutboundManager) AddHandler(_ context.Context, handler outbound.Handler) error {
	if m.handlers == nil {
		m.handlers = make(map[string]outbound.Handler)
	}
	m.handlers[handler.Tag()] = handler
	return nil
}

func (m *vlessReverseOutboundManager) RemoveHandler(_ context.Context, tag string) error {
	delete(m.handlers, tag)
	return nil
}

func (m *vlessReverseOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listed != nil {
		select {
		case <-m.listed:
		default:
			close(m.listed)
		}
	}
	if !m.ready {
		return nil
	}
	return []outbound.Handler{nil}
}

func TestHandlerCloseUnblocksReverseWaitingForOutbound(t *testing.T) {
	const userID = "11223344-5566-7788-99aa-bbccddeeff00"
	account, err := (&vless.Account{Id: userID, Reverse: &vless.Reverse{Tag: "reverse"}}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	memoryAccount := account.(*vless.MemoryAccount)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(&protocol.MemoryUser{Email: "waiting@example.com", Account: memoryAccount}); err != nil {
		t.Fatal(err)
	}
	manager := &vlessReverseOutboundManager{listed: make(chan struct{})}
	handler := &Handler{validator: validator, outboundHandlerManager: manager, ctx: context.Background()}
	getDone := make(chan error, 1)
	go func() {
		_, err := handler.GetReverse(memoryAccount)
		getDone <- err
	}()
	<-manager.listed

	closeDone := make(chan error, 1)
	go func() { closeDone <- handler.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("VLESS inbound close did not cancel reverse construction waiting for an outbound")
	}
	if err := <-getDone; err == nil {
		t.Fatal("reverse construction waiting for an outbound succeeded after close")
	}
}

func TestHandlerCloseRejectsLateReverseRegistration(t *testing.T) {
	const userID = "00112233-4455-6677-8899-aabbccddeeff"
	account, err := (&vless.Account{Id: userID, Reverse: &vless.Reverse{Tag: "reverse"}}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	memoryAccount := account.(*vless.MemoryAccount)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(&protocol.MemoryUser{Email: "reverse@example.com", Account: memoryAccount}); err != nil {
		t.Fatal(err)
	}
	manager := &vlessReverseOutboundManager{}
	handler := &Handler{validator: validator, outboundHandlerManager: manager, ctx: context.Background()}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if reverseOwner, err := handler.GetReverse(memoryAccount); err == nil || reverseOwner != nil {
		t.Fatalf("closed VLESS inbound admitted late reverse owner: owner=%v err=%v", reverseOwner, err)
	}
	if got := manager.GetHandler("reverse"); got != nil {
		t.Fatal("closed VLESS inbound left a late reverse owner registered")
	}
}

type retainingDispatcher struct {
	link     chan *transport.Link
	provider session.PresenceProvider
	subject  chan session.PresenceSubject
}

func (d *retainingDispatcher) PresenceProvider() session.PresenceProvider { return d.provider }

func (*retainingDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, fmt.Errorf("unexpected Dispatch call")
}

func (d *retainingDispatcher) DispatchLink(ctx context.Context, _ X.Destination, link *transport.Link) error {
	if d.provider != nil && d.subject != nil {
		d.subject <- d.provider.SnapshotPresence(ctx).Subject()
	}
	d.link <- link
	return nil
}

func (*retainingDispatcher) Start() error      { return nil }
func (*retainingDispatcher) Close() error      { return nil }
func (*retainingDispatcher) Type() interface{} { return routing.DispatcherType() }

type vlessPresenceProvider struct{}

func (vlessPresenceProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	inbound := session.InboundFromContext(ctx)
	return session.NewPresenceScope(session.PresenceSubject{
		Email: inbound.User.Email, Level: inbound.User.Level, IP: inbound.PhysicalPeer,
	}, vlessPresenceTracker{})
}

type vlessPresenceTracker struct{}

func (vlessPresenceTracker) Prepare(session.PresenceSubject) session.PresenceReservation { return nil }

type noReadDeadlineConnection struct {
	stdnet.Conn
}

func (*noReadDeadlineConnection) SetReadDeadline(time.Time) error { return nil }

func TestVLESSMuxLinkRemainsUsableAfterProcessReturns(t *testing.T) {
	const userID = "00112233-4455-6677-8899-aabbccddeeff"
	account, err := (&vless.Account{Id: userID}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Level: 0, Email: "mux@example.com", Account: account}
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}

	policyManager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{policyManager: policyManager, validator: validator}
	dispatcher := &retainingDispatcher{
		link: make(chan *transport.Link, 1), provider: vlessPresenceProvider{}, subject: make(chan session.PresenceSubject, 1),
	}
	serverPipe, client := stdnet.Pipe()
	server := &noReadDeadlineConnection{Conn: serverPipe}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	ctx := c.ContextWithID(context.Background(), 1)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	ctx = session.ContextWithInbound(
		ctx,
		&session.Inbound{
			Source:       X.TCPDestination(X.ParseAddress("198.51.100.7"), 12345),
			PhysicalPeer: netip.MustParseAddr("192.0.2.9"),
			Local:        X.TCPDestination(X.LocalHostIP, 443),
		},
	)
	ctx = session.ContextWithContent(ctx, &session.Content{})
	processResult := make(chan error, 1)
	go func() {
		processResult <- handler.Process(ctx, X.Network_TCP, server, dispatcher)
	}()

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    user,
		Command: protocol.RequestCommandMux,
		Address: X.DomainAddress("v1.mux.cool"),
	}
	if err := encoding.EncodeRequestHeader(client, request, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}

	select {
	case subject := <-dispatcher.subject:
		if subject.Email != user.Email || subject.Level != user.Level || subject.IP != netip.MustParseAddr("192.0.2.9") {
			t.Fatalf("VLESS authenticated snapshot = %+v", subject)
		}
	case <-time.After(time.Second):
		t.Fatal("VLESS authenticated snapshot was not observed")
	}

	var retained *transport.Link
	select {
	case retained = <-dispatcher.link:
	case <-time.After(time.Second):
		t.Fatal("VLESS request was not dispatched")
	}
	select {
	case err := <-processResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("VLESS Process did not return after dispatcher accepted the link")
	}

	payload := []byte("response-after-dispatch")
	writeResult := make(chan error, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				writeResult <- fmt.Errorf("panic while writing retained VLESS link: %v", recovered)
			}
		}()
		writeResult <- retained.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)})
	}()

	want := append([]byte{encoding.Version, 0}, payload...)
	type readOutcome struct {
		payload []byte
		err     error
	}
	readResult := make(chan readOutcome, 1)
	go func() {
		got := make([]byte, len(want))
		_, err := io.ReadFull(client, got)
		readResult <- readOutcome{payload: got, err: err}
	}()

	var readDone, writeDone bool
	deadline := time.After(time.Second)
	for !readDone || !writeDone {
		select {
		case outcome := <-readResult:
			readDone = true
			if outcome.err != nil {
				t.Fatal(outcome.err)
			}
			if string(outcome.payload) != string(want) {
				t.Fatalf("response = %x, want %x", outcome.payload, want)
			}
		case err := <-writeResult:
			writeDone = true
			if err != nil {
				t.Fatal(err)
			}
		case <-deadline:
			t.Fatal("retained VLESS response writer did not complete")
		}
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("late VLESS request read panicked after Process returned: %v", recovered)
		}
	}()
	mb, err := retained.Reader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err == nil {
		t.Fatal("late VLESS request read unexpectedly succeeded after client close")
	}
}
