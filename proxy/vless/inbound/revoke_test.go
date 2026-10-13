package inbound

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
)

const revokeWait = 5 * time.Second

func newRevokeUser(t *testing.T, email, reverseTag string) *protocol.MemoryUser {
	t.Helper()
	id := uuid.New()
	config := &vless.Account{Id: id.String()}
	if reverseTag != "" {
		config.Reverse = &vless.Reverse{Tag: reverseTag}
	}
	account, err := config.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: email, Account: account}
}

func newRevokeHandler(t *testing.T, validator vless.Validator, manager outbound.Manager) *Handler {
	t.Helper()
	policyManager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{
		policyManager:          policyManager,
		sessionPolicy:          policyManager.ForLevel(0),
		validator:              validator,
		outboundHandlerManager: manager,
		ctx:                    context.Background(),
	}
}

func addRevokeUsers(t *testing.T, handler *Handler, users ...*protocol.MemoryUser) {
	t.Helper()
	for _, user := range users {
		if err := handler.AddUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
}

// revokeDispatcher serves each dispatched link like a copy loop that ignores
// its context: it reads the inbound link until a read fails, which only
// closing the inbound connection causes.
type revokeDispatcher struct {
	dispatched chan string
	payloads   chan string
}

func newRevokeDispatcher() *revokeDispatcher {
	return &revokeDispatcher{dispatched: make(chan string, 16), payloads: make(chan string, 16)}
}

func (*revokeDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, errors.New("unexpected Dispatch call")
}

func (d *revokeDispatcher) DispatchLink(ctx context.Context, _ X.Destination, link *transport.Link) error {
	d.dispatched <- session.InboundFromContext(ctx).User.Email
	for {
		mb, err := link.Reader.ReadMultiBuffer()
		for _, b := range mb {
			if b != nil {
				d.payloads <- b.String()
			}
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			return err
		}
	}
}

func (*revokeDispatcher) Start() error      { return nil }
func (*revokeDispatcher) Close() error      { return nil }
func (*revokeDispatcher) Type() interface{} { return routing.DispatcherType() }

// contextDispatcher holds each link until its context ends, like an outbound
// waiting on a dial or a transport that only the context interrupts.
type contextDispatcher struct {
	dispatched chan string
	canceled   chan string
}

func (*contextDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, errors.New("unexpected Dispatch call")
}

func (d *contextDispatcher) DispatchLink(ctx context.Context, _ X.Destination, _ *transport.Link) error {
	d.dispatched <- session.InboundFromContext(ctx).User.Email
	<-ctx.Done()
	d.canceled <- session.InboundFromContext(ctx).User.Email
	return ctx.Err()
}

func (*contextDispatcher) Start() error      { return nil }
func (*contextDispatcher) Close() error      { return nil }
func (*contextDispatcher) Type() interface{} { return routing.DispatcherType() }

type revokeConnection struct {
	client stdnet.Conn
	done   chan struct{} // closed when Process returns with err
	err    error
}

// startRevokeConnection opens a loopback TCP connection, serves its accepted
// end with handler.Process and sends a VLESS request for user on it.
func startRevokeConnection(t *testing.T, handler *Handler, dispatcher routing.Dispatcher, user *protocol.MemoryUser, command protocol.RequestCommand, payload string) *revokeConnection {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := stdnet.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	connection := &revokeConnection{client: client, done: make(chan struct{})}
	t.Cleanup(func() {
		client.Close()
		server.Close()
		select {
		case <-connection.done:
		case <-time.After(revokeWait):
			t.Error("VLESS Process did not return after its connection was closed")
		}
	})

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: X.DestinationFromAddr(client.LocalAddr()),
		Tag:    "vless-in",
	})
	ctx = session.ContextWithContent(ctx, &session.Content{})
	go func() {
		connection.err = handler.Process(ctx, X.Network_TCP, server, dispatcher)
		// The proxyman worker closes the connection once Process returns.
		server.Close()
		close(connection.done)
	}()

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    user,
		Command: command,
		Address: X.LocalHostIP,
		Port:    X.Port(80),
	}
	if command == protocol.RequestCommandRvs {
		request.Address = X.DomainAddress("v1.rvs.cool")
		request.Port = 0
	}
	if err := encoding.EncodeRequestHeader(client, request, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	if payload != "" {
		if _, err := client.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	return connection
}

func (c *revokeConnection) requireEnded(t *testing.T, name string) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(revokeWait):
		t.Fatalf("%s: Process still serves the connection %v after RemoveUser", name, revokeWait)
	}
	if err := c.client.SetReadDeadline(time.Now().Add(revokeWait)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, c.client); err != nil {
		var netErr stdnet.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("%s: the client connection is still open %v after RemoveUser", name, revokeWait)
		}
	}
}

func (c *revokeConnection) requireServing(t *testing.T, name string) {
	t.Helper()
	select {
	case <-c.done:
		t.Fatalf("%s: Process returned: %v", name, c.err)
	default:
	}
}

func receive(t *testing.T, channel <-chan string, want, name string) {
	t.Helper()
	deadline := time.After(revokeWait)
	for {
		select {
		case got := <-channel:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("%s: %q not received", name, want)
		}
	}
}

func TestRemoveUserClosesTheRemovedUsersConnections(t *testing.T) {
	validator := new(vless.MemoryValidator)
	handler := newRevokeHandler(t, validator, &revokeOutboundManager{})
	victim := newRevokeUser(t, "Victim@Example.com", "")
	bystander := newRevokeUser(t, "bystander@example.com", "")
	addRevokeUsers(t, handler, victim, bystander)
	dispatcher := newRevokeDispatcher()

	victims := make([]*revokeConnection, 2)
	for i := range victims {
		payload := "victim-" + strconv.Itoa(i)
		victims[i] = startRevokeConnection(t, handler, dispatcher, victim, protocol.RequestCommandTCP, payload)
		receive(t, dispatcher.payloads, payload, "victim before removal")
	}
	survivor := startRevokeConnection(t, handler, dispatcher, bystander, protocol.RequestCommandTCP, "bystander-0")
	receive(t, dispatcher.payloads, "bystander-0", "bystander before removal")

	if err := handler.RemoveUser(context.Background(), "victim@example.com"); err != nil {
		t.Fatal(err)
	}

	for i, connection := range victims {
		connection.requireEnded(t, "victim connection "+strconv.Itoa(i))
	}
	survivor.requireServing(t, "bystander")
	if _, err := survivor.client.Write([]byte("bystander-1")); err != nil {
		t.Fatalf("bystander: %v", err)
	}
	receive(t, dispatcher.payloads, "bystander-1", "bystander after removal")
}

func TestRemoveUserCancelsTheConnectionContext(t *testing.T) {
	validator := new(vless.MemoryValidator)
	handler := newRevokeHandler(t, validator, &revokeOutboundManager{})
	victim := newRevokeUser(t, "victim@example.com", "")
	addRevokeUsers(t, handler, victim)
	dispatcher := &contextDispatcher{dispatched: make(chan string, 1), canceled: make(chan string, 1)}

	connection := startRevokeConnection(t, handler, dispatcher, victim, protocol.RequestCommandTCP, "")
	receive(t, dispatcher.dispatched, victim.Email, "victim before removal")
	if err := handler.RemoveUser(context.Background(), victim.Email); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatcher.canceled:
	case <-time.After(revokeWait):
		t.Fatalf("the context of a removed user's connection is still live %v after RemoveUser", revokeWait)
	}
	connection.requireEnded(t, "victim")
}

// authenticationHookValidator runs hook after the validator authenticates a
// request, before Process has registered the connection.
type authenticationHookValidator struct {
	vless.Validator
	once sync.Once
	hook func(*protocol.MemoryUser)
}

func (v *authenticationHookValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	user := v.Validator.Get(id)
	if user != nil {
		v.once.Do(func() { v.hook(user) })
	}
	return user
}

func TestRemoveUserRejectsAnAuthenticationItOverlapped(t *testing.T) {
	for _, readd := range []bool{false, true} {
		name := "removed"
		if readd {
			name = "removed and added again"
		}
		t.Run(name, func(t *testing.T) {
			validator := &authenticationHookValidator{Validator: new(vless.MemoryValidator)}
			handler := newRevokeHandler(t, validator, &revokeOutboundManager{})
			victim := newRevokeUser(t, "victim@example.com", "")
			addRevokeUsers(t, handler, victim)
			validator.hook = func(authenticated *protocol.MemoryUser) {
				if err := handler.RemoveUser(context.Background(), victim.Email); err != nil {
					t.Error(err)
				}
				if readd {
					// The API hands a fresh MemoryUser to every AddUser; an
					// embedding program may hand back the authenticated one.
					if err := handler.AddUser(context.Background(), authenticated); err != nil {
						t.Error(err)
					}
				}
			}
			dispatcher := newRevokeDispatcher()

			connection := startRevokeConnection(t, handler, dispatcher, victim, protocol.RequestCommandTCP, "stale")
			select {
			case <-connection.done:
				if connection.err == nil {
					t.Fatal("Process accepted a connection whose user was removed while it authenticated")
				}
			case email := <-dispatcher.dispatched:
				t.Fatalf("dispatched a connection of %s, removed while it authenticated", email)
			case <-time.After(revokeWait):
				t.Fatal("Process neither rejected nor dispatched the connection")
			}
		})
	}
}

// lookupHookValidator blocks the first GetByEmail of RemoveUser until the
// test releases it.
type lookupHookValidator struct {
	vless.Validator
	hooked  atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (v *lookupHookValidator) GetByEmail(email string) *protocol.MemoryUser {
	user := v.Validator.GetByEmail(email)
	// Not sync.Once: a concurrent Do would wait for this one.
	if v.hooked.CompareAndSwap(false, true) {
		close(v.entered)
		<-v.release
	}
	return user
}

// TestRemoveUserIsAtomicWithAddUser races a RemoveUser that has looked up its
// user against another RemoveUser and an AddUser of the same email. Whatever
// order the inbound applies them in, the email must not end up removed while
// a connection of it still runs.
func TestRemoveUserIsAtomicWithAddUser(t *testing.T) {
	// Without serialization the second RemoveUser and the AddUser finish
	// within this window; with it they wait for the first RemoveUser.
	const raceWindow = 200 * time.Millisecond
	validator := &lookupHookValidator{
		Validator: new(vless.MemoryValidator),
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	handler := newRevokeHandler(t, validator, &revokeOutboundManager{})
	first := newRevokeUser(t, "user@example.com", "")
	second := newRevokeUser(t, "user@example.com", "")
	if err := validator.Validator.Add(first); err != nil {
		t.Fatal(err)
	}
	dispatcher := newRevokeDispatcher()

	firstRemove := make(chan error, 1)
	go func() { firstRemove <- handler.RemoveUser(context.Background(), first.Email) }()
	<-validator.entered

	readded := make(chan error, 1)
	go func() {
		_ = handler.RemoveUser(context.Background(), first.Email)
		readded <- handler.AddUser(context.Background(), second)
	}()
	var connection *revokeConnection
	select {
	case err := <-readded:
		// Not serialized: the email was removed and added again while the
		// first RemoveUser holds its lookup. Connect before it continues.
		if err != nil {
			t.Fatal(err)
		}
		connection = startRevokeConnection(t, handler, dispatcher, second, protocol.RequestCommandTCP, "second")
		receive(t, dispatcher.payloads, "second", "added user")
	case <-time.After(raceWindow):
	}
	close(validator.release)
	if err := <-firstRemove; err != nil {
		t.Fatal(err)
	}
	if connection == nil {
		select {
		case err := <-readded:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(revokeWait):
			t.Fatal("AddUser did not return")
		}
		connection = startRevokeConnection(t, handler, dispatcher, second, protocol.RequestCommandTCP, "second")
		receive(t, dispatcher.payloads, "second", "added user")
	}

	if handler.GetUser(context.Background(), second.Email) != nil {
		connection.requireServing(t, "connection of the added user")
		return
	}
	connection.requireEnded(t, "connection of a removed email")
}

type revokeOutboundManager struct {
	mu       sync.Mutex
	handlers map[string]outbound.Handler
	ready    bool
	// onLookup runs once, on the first GetHandler.
	onLookup func()
	looked   atomic.Bool
	// onAdd runs after each AddHandler.
	onAdd func()
}

func (*revokeOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (*revokeOutboundManager) Start() error      { return nil }
func (*revokeOutboundManager) Close() error      { return nil }

func (m *revokeOutboundManager) GetHandler(tag string) outbound.Handler {
	if m.onLookup != nil && m.looked.CompareAndSwap(false, true) {
		m.onLookup()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handlers[tag]
}

func (*revokeOutboundManager) GetDefaultHandler() outbound.Handler { return nil }

func (m *revokeOutboundManager) AddHandler(_ context.Context, handler outbound.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handlers == nil {
		m.handlers = make(map[string]outbound.Handler)
	}
	m.handlers[handler.Tag()] = handler
	if m.onAdd != nil {
		m.onAdd()
	}
	return nil
}

func (m *revokeOutboundManager) RemoveHandler(_ context.Context, tag string) error {
	m.mu.Lock()
	handler := m.handlers[tag]
	delete(m.handlers, tag)
	m.mu.Unlock()
	if handler != nil {
		return handler.Close()
	}
	return nil
}

func (m *revokeOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return nil
	}
	return []outbound.Handler{nil}
}

func (m *revokeOutboundManager) setReady() {
	m.mu.Lock()
	m.ready = true
	m.mu.Unlock()
}

func TestRemoveUserStopsAReverseWaitingToPublish(t *testing.T) {
	validator := new(vless.MemoryValidator)
	manager := &revokeOutboundManager{}
	handler := newRevokeHandler(t, validator, manager)
	victim := newRevokeUser(t, "victim@example.com", "reverse")
	addRevokeUsers(t, handler, victim)
	looked := make(chan struct{})
	manager.onLookup = func() { close(looked) }

	// The outbound manager is not ready, so the reverse waits before it
	// publishes its outbound.
	connection := startRevokeConnection(t, handler, newRevokeDispatcher(), victim, protocol.RequestCommandRvs, "")
	<-looked
	if err := handler.RemoveUser(context.Background(), victim.Email); err != nil {
		t.Fatal(err)
	}

	connection.requireEnded(t, "reverse bridge of the removed user, waiting for outbounds")
	manager.setReady()
	if handler := manager.GetHandler("reverse"); handler != nil {
		t.Fatal("published the reverse outbound of a removed user")
	}
}

// TestRemoveUserEndsAReverseBridgeWithoutRacingItsReader removes the user of a
// published reverse bridge. Process returns on the canceled context while the
// bridge's mux worker still reads the connection through Process's reader, so
// Process must leave that reader alone; -race reports it if Process releases
// the reader's buffers.
func TestRemoveUserEndsAReverseBridgeWithoutRacingItsReader(t *testing.T) {
	validator := new(vless.MemoryValidator)
	published := make(chan struct{})
	var publishOnce sync.Once
	manager := &revokeOutboundManager{ready: true}
	manager.onAdd = func() { publishOnce.Do(func() { close(published) }) }
	handler := newRevokeHandler(t, validator, manager)
	victim := newRevokeUser(t, "victim@example.com", "reverse")
	addRevokeUsers(t, handler, victim)

	connection := startRevokeConnection(t, handler, newRevokeDispatcher(), victim, protocol.RequestCommandRvs, "")
	select {
	case <-published:
	case <-time.After(revokeWait):
		t.Fatal("the reverse bridge did not publish its outbound")
	}
	if err := handler.RemoveUser(context.Background(), victim.Email); err != nil {
		t.Fatal(err)
	}
	connection.requireEnded(t, "published reverse bridge of the removed user")
}

func TestRemoveUserBeforeAReversePublishesKeepsItUnpublished(t *testing.T) {
	validator := new(vless.MemoryValidator)
	manager := &revokeOutboundManager{ready: true}
	handler := newRevokeHandler(t, validator, manager)
	victim := newRevokeUser(t, "victim@example.com", "reverse")
	addRevokeUsers(t, handler, victim)
	// The reverse bridge has authenticated and looks its outbound up when
	// its user is removed.
	manager.onLookup = func() {
		if err := handler.RemoveUser(context.Background(), victim.Email); err != nil {
			t.Error(err)
		}
	}

	connection := startRevokeConnection(t, handler, newRevokeDispatcher(), victim, protocol.RequestCommandRvs, "")
	connection.requireEnded(t, "reverse bridge of the removed user")
	if handler := manager.GetHandler("reverse"); handler != nil {
		t.Fatal("published the reverse outbound of a removed user")
	}
}

type closeCountingOutbound struct {
	tag    string
	mu     sync.Mutex
	closes int
}

func (h *closeCountingOutbound) Tag() string                             { return h.tag }
func (*closeCountingOutbound) Start() error                              { return nil }
func (*closeCountingOutbound) Dispatch(context.Context, *transport.Link) {}
func (*closeCountingOutbound) SenderSettings() *serial.TypedMessage      { return nil }
func (*closeCountingOutbound) ProxySettings() *serial.TypedMessage       { return nil }

func (h *closeCountingOutbound) Close() error {
	h.mu.Lock()
	h.closes++
	h.mu.Unlock()
	return nil
}

func (h *closeCountingOutbound) closeCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closes
}

func TestRemoveUserKeepsAReverseAnotherUserShares(t *testing.T) {
	validator := new(vless.MemoryValidator)
	manager := &revokeOutboundManager{}
	handler := newRevokeHandler(t, validator, manager)
	first := newRevokeUser(t, "first@example.com", "shared")
	second := newRevokeUser(t, "second@example.com", "shared")
	addRevokeUsers(t, handler, first, second)
	shared := &closeCountingOutbound{tag: "shared"}
	if err := manager.AddHandler(context.Background(), shared); err != nil {
		t.Fatal(err)
	}

	if err := handler.RemoveUser(context.Background(), first.Email); err != nil {
		t.Fatal(err)
	}
	if manager.GetHandler("shared") != shared || shared.closeCount() != 0 {
		t.Fatalf("removing one user of a shared reverse tag removed the reverse (closed %d times)", shared.closeCount())
	}

	if err := handler.RemoveUser(context.Background(), second.Email); err != nil {
		t.Fatal(err)
	}
	if manager.GetHandler("shared") != nil || shared.closeCount() == 0 {
		t.Fatal("removing the last user of a reverse tag kept the reverse")
	}
}

func TestRemoveUserKeepsAReverseAUserWithoutEmailShares(t *testing.T) {
	validator := new(vless.MemoryValidator)
	manager := &revokeOutboundManager{}
	handler := newRevokeHandler(t, validator, manager)
	named := newRevokeUser(t, "named@example.com", "shared")
	// A user without an email cannot be removed, so its reverse must stay.
	anonymous := newRevokeUser(t, "", "shared")
	addRevokeUsers(t, handler, named, anonymous)
	shared := &closeCountingOutbound{tag: "shared"}
	if err := manager.AddHandler(context.Background(), shared); err != nil {
		t.Fatal(err)
	}

	if err := handler.RemoveUser(context.Background(), named.Email); err != nil {
		t.Fatal(err)
	}
	if manager.GetHandler("shared") != shared || shared.closeCount() != 0 {
		t.Fatalf("removing a user removed the reverse a user without an email shares (closed %d times)", shared.closeCount())
	}
}

func TestRemoveUserKeepsAReverseAUserWithASharedUUIDKeeps(t *testing.T) {
	validator := new(vless.MemoryValidator)
	manager := &revokeOutboundManager{}
	handler := newRevokeHandler(t, validator, manager)
	removed := newRevokeUser(t, "removed@example.com", "shared")
	kept := newRevokeUser(t, "kept@example.com", "shared")
	// The validator accepts a second user with kept's UUID: authentication
	// then finds the newer user, but kept stays a user of the inbound under
	// its email, with its connections and its reverse.
	shadow := newRevokeUser(t, "shadow@example.com", "other")
	shadow.Account.(*vless.MemoryAccount).ID = kept.Account.(*vless.MemoryAccount).ID
	addRevokeUsers(t, handler, removed, kept, shadow)
	shared := &closeCountingOutbound{tag: "shared"}
	if err := manager.AddHandler(context.Background(), shared); err != nil {
		t.Fatal(err)
	}

	if err := handler.RemoveUser(context.Background(), removed.Email); err != nil {
		t.Fatal(err)
	}
	if manager.GetHandler("shared") != shared || shared.closeCount() != 0 {
		t.Fatalf("removing a user removed the reverse of a user whose UUID another user shares (closed %d times)", shared.closeCount())
	}
}
