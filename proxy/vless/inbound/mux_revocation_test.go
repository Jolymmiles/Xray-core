package inbound

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	policyapp "github.com/xtls/xray-core/app/policy"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
)

func revocationUser(t *testing.T, email, id string) *protocol.MemoryUser {
	t.Helper()
	account, err := (&vless.Account{Id: id}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: email, Account: account}
}

func revocationHandler(t *testing.T, users ...*protocol.MemoryUser) *Handler {
	t.Helper()
	validator := new(vless.MemoryValidator)
	for _, user := range users {
		if err := validator.Add(user); err != nil {
			t.Fatal(err)
		}
	}
	policies, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{validator: validator, policyManager: policies, ctx: context.Background()}
}

type revocationDispatcher struct {
	retainingDispatcher
	entered chan context.Context
	release chan struct{}
	once    sync.Once
}

func (d *revocationDispatcher) DispatchLink(ctx context.Context, _ X.Destination, _ *transport.Link) error {
	d.entered <- ctx
	<-d.release
	return nil
}

func (d *revocationDispatcher) finish() { d.once.Do(func() { close(d.release) }) }

type revocationProcess struct {
	client   net.Conn
	server   net.Conn
	dispatch *revocationDispatcher
	done     chan error
}

type revocationConnection struct {
	*noReadDeadlineConnection
	beforeClose func()
}

func (c *revocationConnection) Close() error {
	if c.beforeClose != nil {
		c.beforeClose()
	}
	return c.Conn.Close()
}

func startRevocationProcess(t *testing.T, h *Handler, user *protocol.MemoryUser, kind string) *revocationProcess {
	t.Helper()
	server, client := net.Pipe()
	dispatch := &revocationDispatcher{entered: make(chan context.Context, 1), release: make(chan struct{})}
	connection := &revocationConnection{noReadDeadlineConnection: &noReadDeadlineConnection{Conn: server}}
	p := &revocationProcess{client: client, server: connection, dispatch: dispatch, done: make(chan error, 1)}
	finished := make(chan struct{})
	t.Cleanup(func() {
		dispatch.finish()
		_ = client.Close()
		_ = server.Close()
		awaitRevocation(t, finished)
	})
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	ctx = session.ContextWithContent(ctx, &session.Content{})
	go func() {
		defer close(finished)
		p.done <- h.Process(ctx, X.Network_TCP, connection, dispatch)
	}()
	request := &protocol.RequestHeader{Version: encoding.Version, User: user, Command: protocol.RequestCommandTCP, Address: X.DomainAddress("example.com"), Port: 443}
	switch kind {
	case "native":
		request.Command = protocol.RequestCommandMux
		request.Address = X.DomainAddress("v1.mux.cool")
	case "native-tcp":
		request.Address = X.DomainAddress("v1.mux.cool")
	case "smux":
		request.Address = X.DomainAddress("sp.mux.sing-box.arpa")
		request.Port = 444
	}
	if err := encoding.EncodeRequestHeader(client, request, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	return p
}

func awaitRevocation[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("revocation lifecycle barrier did not complete")
		var zero T
		return zero
	}
}

func assertRevoked(t *testing.T, p *revocationProcess, ctx context.Context) {
	t.Helper()
	if ctx.Err() != context.Canceled {
		t.Errorf("removed MUX carrier context is still live: %v", ctx.Err())
	}
	if err := p.client.SetReadDeadline(time.Now().Add(time.Second)); err != nil && err != io.ErrClosedPipe {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := p.client.Read(one[:]); err != io.EOF {
		t.Errorf("removed physical carrier was not closed before RemoveUser returned: %v", err)
	}
}

// Removing only validator credentials leaves an authenticated physical carrier live.
func TestMUXRevocationRegisteredCarrier(t *testing.T) {
	for _, kind := range []string{"native", "native-tcp", "smux"} {
		t.Run(kind, func(t *testing.T) {
			u := revocationUser(t, "removed@example.com", "00112233-4455-6677-8899-aabbccddeeff")
			h := revocationHandler(t, u)
			first := startRevocationProcess(t, h, u, kind)
			firstCtx := awaitRevocation(t, first.dispatch.entered)
			second := startRevocationProcess(t, h, u, kind)
			secondCtx := awaitRevocation(t, second.dispatch.entered)
			if err := h.RemoveUser(context.Background(), "REMOVED@example.com"); err != nil {
				t.Fatal(err)
			}
			if h.GetUser(context.Background(), u.Email) != nil {
				t.Fatal("removed credential remains registered")
			}
			assertRevoked(t, first, firstCtx)
			assertRevoked(t, second, secondCtx)
		})
	}
}

// The auth barrier represents a completed UUID lookup before carrier registration.
type pausedRevocationValidator struct {
	vless.Validator
	observed chan struct{}
	resume   chan struct{}
}

func (v *pausedRevocationValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	u := v.Validator.Get(id)
	close(v.observed)
	<-v.resume
	return u
}

func TestMUXRevocationRejectsStaleAuthentication(t *testing.T) {
	for _, kind := range []string{"native", "native-tcp", "smux"} {
		for _, replacement := range []string{"none", "same-uuid", "new-uuid", "same-pointer"} {
			t.Run(kind+"/"+replacement, func(t *testing.T) {
				u := revocationUser(t, "removed@example.com", "00112233-4455-6677-8899-aabbccddeeff")
				h := revocationHandler(t, u)
				paused := &pausedRevocationValidator{Validator: h.validator, observed: make(chan struct{}), resume: make(chan struct{})}
				h.validator = paused
				p := startRevocationProcess(t, h, u, kind)
				awaitRevocation(t, paused.observed)
				if err := h.RemoveUser(context.Background(), u.Email); err != nil {
					t.Fatal(err)
				}
				if replacement != "none" {
					next := u
					if replacement == "same-uuid" {
						next = revocationUser(t, u.Email, "00112233-4455-6677-8899-aabbccddeeff")
					} else if replacement == "new-uuid" {
						next = revocationUser(t, u.Email, "11112233-4455-6677-8899-aabbccddeeff")
					}
					if err := h.AddUser(context.Background(), next); err != nil {
						t.Fatal(err)
					}
				}
				close(paused.resume)
				// Let the baseline dispatcher return so failure cannot be a timeout.
				p.dispatch.finish()
				if err := awaitRevocation(t, p.done); err == nil {
					t.Error("pre-removal authentication dispatched after removal/re-add")
				}
				select {
				case <-p.dispatch.entered:
					t.Error("stale authenticated identity reached dispatcher")
				default:
				}
			})
		}
	}
}

func TestMUXRevocationPreservesOtherOwnersAndNoMux(t *testing.T) {
	removed := revocationUser(t, "same@example.com", "00112233-4455-6677-8899-aabbccddeeff")
	peer := revocationUser(t, "", "11112233-4455-6677-8899-aabbccddeeff")
	other := revocationUser(t, "other@example.com", "22112233-4455-6677-8899-aabbccddeeff")
	h := revocationHandler(t, removed, peer, other)
	secondHandler := revocationHandler(t, removed)
	for _, scenario := range []struct {
		name    string
		handler *Handler
		user    *protocol.MemoryUser
		kind    string
	}{
		{"static", h, peer, "smux"}, {"other-user", h, other, "native"},
		{"other-inbound", secondHandler, removed, "smux"}, {"no-mux", h, removed, "direct"},
	} {
		p := startRevocationProcess(t, scenario.handler, scenario.user, scenario.kind)
		ctx := awaitRevocation(t, p.dispatch.entered)
		t.Cleanup(func() {
			if ctx.Err() != nil {
				t.Errorf("%s was canceled by unrelated removal", scenario.name)
			}
		})
	}
	if err := h.RemoveUser(context.Background(), removed.Email); err != nil {
		t.Fatal(err)
	}
}

func TestMUXRevocationUnregisterOnReturn(t *testing.T) {
	u := revocationUser(t, "removed@example.com", "00112233-4455-6677-8899-aabbccddeeff")
	h := revocationHandler(t, u)
	p := startRevocationProcess(t, h, u, "native")
	ctx := awaitRevocation(t, p.dispatch.entered)
	p.dispatch.finish()
	if err := awaitRevocation(t, p.done); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != context.Canceled {
		t.Error("returned handler retained its child context")
	}
	if err := h.RemoveUser(context.Background(), u.Email); err != nil {
		t.Fatal(err)
	}
	// A finished registration must not retain its physical connection for later removal.
	written := make(chan error, 1)
	go func() { _, err := p.server.Write([]byte{42}); written <- err }()
	_ = p.client.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := io.ReadFull(p.client, one[:]); err != nil || one[0] != 42 {
		t.Fatalf("returned handler's connection was retained for removal: byte=%d error=%v", one[0], err)
	}
	if err := awaitRevocation(t, written); err != nil {
		t.Fatal(err)
	}
}

func TestMUXRevocationHandlerClose(t *testing.T) {
	u := revocationUser(t, "removed@example.com", "00112233-4455-6677-8899-aabbccddeeff")
	h := revocationHandler(t, u)
	p := startRevocationProcess(t, h, u, "smux")
	ctx := awaitRevocation(t, p.dispatch.entered)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, p, ctx)
	if err := h.AddUser(context.Background(), revocationUser(t, "late@example.com", "11112233-4455-6677-8899-aabbccddeeff")); err == nil {
		t.Error("closed handler admitted a new user")
	}
}

// A blocked physical Close must not hold the mutation lock or capture a new incarnation.
func TestMUXRevocationReAddWhileOldCarrierCloses(t *testing.T) {
	u := revocationUser(t, "removed@example.com", "00112233-4455-6677-8899-aabbccddeeff")
	h := revocationHandler(t, u)
	p := startRevocationProcess(t, h, u, "native")
	oldCtx := awaitRevocation(t, p.dispatch.entered)
	closing, resume := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	unblock := func() { resumeOnce.Do(func() { close(resume) }) }
	t.Cleanup(unblock)
	p.server.(*revocationConnection).beforeClose = func() { close(closing); <-resume }
	removed := make(chan error, 1)
	go func() { removed <- h.RemoveUser(context.Background(), u.Email) }()
	select {
	case <-closing:
	case err := <-removed:
		t.Fatalf("RemoveUser returned without physically closing its carrier: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("carrier close did not begin")
	}
	added := make(chan error, 1)
	go func() { added <- h.AddUser(context.Background(), u) }()
	if err := awaitRevocation(t, added); err != nil {
		t.Fatal(err)
	}
	fresh := startRevocationProcess(t, h, u, "smux")
	freshCtx := awaitRevocation(t, fresh.dispatch.entered)
	unblock()
	if err := awaitRevocation(t, removed); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, p, oldCtx)
	if freshCtx.Err() != nil {
		t.Fatal("new incarnation was canceled with the old carrier")
	}
	if err := h.RemoveUser(context.Background(), u.Email); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, fresh, freshCtx)
}
