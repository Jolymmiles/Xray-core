package inbound

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

const revokeWait = 5 * time.Second

func newRevokeUser(t *testing.T, email string) *protocol.MemoryUser {
	t.Helper()
	id := uuid.New()
	account, err := (&vmess.Account{
		Id:               id.String(),
		SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM},
	}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: email, Account: account}
}

func newRevokeHandler(t *testing.T, users ...*protocol.MemoryUser) *Handler {
	t.Helper()
	handler := &Handler{
		policyManager:  policy.DefaultManager{},
		clients:        vmess.NewTimedUserValidator(),
		usersByEmail:   newUserByEmail(&DefaultConfig{}),
		sessionHistory: encoding.NewSessionHistory(),
	}
	t.Cleanup(func() { _ = handler.Close() })
	for _, user := range users {
		if err := handler.AddUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	return handler
}

// revokeDispatcher hands out links whose uplink it drains, reporting each
// payload.
type revokeDispatcher struct {
	dispatched chan string
	payloads   chan string
}

func newRevokeDispatcher() *revokeDispatcher {
	return &revokeDispatcher{dispatched: make(chan string, 16), payloads: make(chan string, 16)}
}

func (d *revokeDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.dispatched <- session.InboundFromContext(ctx).User.Email
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	go func() {
		defer downlinkWriter.Close()
		for {
			mb, err := uplinkReader.ReadMultiBuffer()
			for _, b := range mb {
				if b != nil {
					d.payloads <- b.String()
				}
			}
			buf.ReleaseMulti(mb)
			if err != nil {
				return
			}
		}
	}()
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

func (*revokeDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return errors.New("unexpected DispatchLink call")
}

func (*revokeDispatcher) Start() error      { return nil }
func (*revokeDispatcher) Close() error      { return nil }
func (*revokeDispatcher) Type() interface{} { return routing.DispatcherType() }

// authGateConn is the accepted end of a connection. Process clears its
// handshake read deadline once DecodeRequestHeader has authenticated the
// request and before it tracks the connection. A gated connection reports
// that call and holds Process in it until released.
type authGateConn struct {
	stdnet.Conn
	authenticated chan struct{}
	release       chan struct{} // nil: never hold
}

func (c *authGateConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() && c.release != nil {
		select {
		case c.authenticated <- struct{}{}:
		default:
		}
		<-c.release
	}
	return c.Conn.SetReadDeadline(deadline)
}

type revokeConnection struct {
	client  stdnet.Conn
	server  *authGateConn
	release func()
	body    buf.Writer
	done    chan struct{} // closed when Process returns with err
	err     error
}

// startRevokeConnection serves the accepted end of a loopback TCP connection
// with handler.Process. A gated connection holds Process after it
// authenticated the request until release.
func startRevokeConnection(t *testing.T, handler *Handler, dispatcher routing.Dispatcher, gated bool) *revokeConnection {
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
	accepted, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	connection := &revokeConnection{
		client:  client,
		server:  &authGateConn{Conn: accepted, authenticated: make(chan struct{}, 1)},
		release: func() {},
		done:    make(chan struct{}),
	}
	if gated {
		release := make(chan struct{})
		connection.server.release = release
		connection.release = sync.OnceFunc(func() { close(release) })
	}
	t.Cleanup(func() {
		connection.release()
		client.Close()
		accepted.Close()
		select {
		case <-connection.done:
		case <-time.After(revokeWait):
			t.Error("VMess Process did not return after its connection was closed")
		}
	})

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.DestinationFromAddr(client.LocalAddr()),
		Tag:    "vmess-in",
	})
	go func() {
		connection.err = handler.Process(ctx, net.Network_TCP, connection.server, dispatcher)
		// The proxyman worker closes the connection once Process returns.
		accepted.Close()
		close(connection.done)
	}()
	return connection
}

// open sends a VMess request header for user and then payload as the first
// body chunk.
func (c *revokeConnection) open(t *testing.T, user *protocol.MemoryUser, payload string) {
	t.Helper()
	request := &protocol.RequestHeader{
		Version:  encoding.Version,
		User:     user,
		Command:  protocol.RequestCommandTCP,
		Address:  net.LocalHostIP,
		Port:     80,
		Security: protocol.SecurityType_AES128_GCM,
		Option:   protocol.RequestOptionChunkStream,
	}
	clientSession := encoding.NewClientSession(context.Background(), 0)
	if err := clientSession.EncodeRequestHeader(request, c.client); err != nil {
		t.Fatal(err)
	}
	body, err := clientSession.EncodeRequestBody(request, c.client)
	if err != nil {
		t.Fatal(err)
	}
	c.body = body
	c.send(t, payload)
}

func (c *revokeConnection) send(t *testing.T, payload string) {
	t.Helper()
	if err := c.body.WriteMultiBuffer(buf.MergeBytes(nil, []byte(payload))); err != nil {
		t.Fatal(err)
	}
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
	victim := newRevokeUser(t, "Victim@Example.com")
	bystander := newRevokeUser(t, "bystander@example.com")
	handler := newRevokeHandler(t, victim, bystander)
	dispatcher := newRevokeDispatcher()

	victims := make([]*revokeConnection, 2)
	for i := range victims {
		payload := "victim-" + strconv.Itoa(i)
		victims[i] = startRevokeConnection(t, handler, dispatcher, false)
		victims[i].open(t, victim, payload)
		receive(t, dispatcher.payloads, payload, "victim before removal")
	}
	survivor := startRevokeConnection(t, handler, dispatcher, false)
	survivor.open(t, bystander, "bystander-0")
	receive(t, dispatcher.payloads, "bystander-0", "bystander before removal")

	if err := handler.RemoveUser(context.Background(), "victim@example.com"); err != nil {
		t.Fatal(err)
	}

	for i, connection := range victims {
		connection.requireEnded(t, "victim connection "+strconv.Itoa(i))
	}
	select {
	case <-survivor.done:
		t.Fatalf("bystander: Process returned: %v", survivor.err)
	default:
	}
	survivor.send(t, "bystander-1")
	receive(t, dispatcher.payloads, "bystander-1", "bystander after removal")
}

func TestRemoveUserRejectsAnAuthenticationItOverlapped(t *testing.T) {
	for _, readd := range []bool{false, true} {
		name := "removed"
		if readd {
			name = "removed and added again"
		}
		t.Run(name, func(t *testing.T) {
			victim := newRevokeUser(t, "victim@example.com")
			handler := newRevokeHandler(t, victim)
			authenticated := handler.GetUser(context.Background(), victim.Email)
			dispatcher := newRevokeDispatcher()
			connection := startRevokeConnection(t, handler, dispatcher, true)

			// Process authenticates the whole request header, then holds in
			// the gate before it tracks the connection.
			connection.open(t, victim, "stale")
			select {
			case <-connection.server.authenticated:
			case <-connection.done:
				t.Fatalf("Process returned before it authenticated the request: %v", connection.err)
			case <-time.After(revokeWait):
				t.Fatal("Process did not authenticate the request")
			}
			if err := handler.RemoveUser(context.Background(), victim.Email); err != nil {
				t.Fatal(err)
			}
			if readd {
				// The API hands a fresh MemoryUser to every AddUser; an
				// embedding program may hand back the authenticated one.
				if err := handler.AddUser(context.Background(), authenticated); err != nil {
					t.Fatal(err)
				}
			}
			connection.release()

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

// TestUserChangesAreSerialized holds the lock AddUser and RemoveUser share.
// RemoveUser looks a user up, deletes it and revokes its connections; if
// another AddUser or RemoveUser ran in between, it could delete the user the
// AddUser stored and revoke the connections of the one it looked up.
// TestRemoveUserIsAtomicWithAddUser in proxy/vless/inbound races the same
// steps through a validator hook, which the VMess user maps do not allow.
func TestUserChangesAreSerialized(t *testing.T) {
	victim := newRevokeUser(t, "victim@example.com")
	readded := newRevokeUser(t, "victim@example.com")
	handler := newRevokeHandler(t, victim)

	for _, change := range []struct {
		name string
		run  func() error
	}{
		{"RemoveUser", func() error { return handler.RemoveUser(context.Background(), victim.Email) }},
		{"AddUser", func() error { return handler.AddUser(context.Background(), readded) }},
	} {
		handler.userMu.Lock()
		done := make(chan error, 1)
		go func() { done <- change.run() }()
		select {
		case err := <-done:
			handler.userMu.Unlock()
			t.Fatalf("%s ran while another user change held the lock (err %v)", change.name, err)
		case <-time.After(100 * time.Millisecond):
		}
		handler.userMu.Unlock()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", change.name, err)
			}
		case <-time.After(revokeWait):
			t.Fatalf("%s did not return after the lock was released", change.name)
		}
	}
}
