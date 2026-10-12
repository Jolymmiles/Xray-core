package trojan

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

const revokeWait = 5 * time.Second

func newRevokeUser(t *testing.T, email string) *protocol.MemoryUser {
	t.Helper()
	account, err := (&Account{Password: email + "-password"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: email, Account: account}
}

func newRevokeServer(t *testing.T, users ...*protocol.MemoryUser) *Server {
	t.Helper()
	policyManager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{policyManager: policyManager, validator: new(Validator)}
	for _, user := range users {
		if err := server.AddUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	return server
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

// readCountingConn reports each Read call before it blocks.
type readCountingConn struct {
	stdnet.Conn
	reads atomic.Int32
	read  chan int32
}

func (c *readCountingConn) Read(b []byte) (int, error) {
	select {
	case c.read <- c.reads.Add(1):
	default:
	}
	return c.Conn.Read(b)
}

type revokeConnection struct {
	client stdnet.Conn
	server *readCountingConn
	done   chan struct{} // closed when Process returns with err
	err    error
}

// startRevokeConnection serves the accepted end of a loopback TCP connection
// with server.Process.
func startRevokeConnection(t *testing.T, server *Server, dispatcher routing.Dispatcher) *revokeConnection {
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
		client: client,
		server: &readCountingConn{Conn: accepted, read: make(chan int32, 16)},
		done:   make(chan struct{}),
	}
	t.Cleanup(func() {
		client.Close()
		accepted.Close()
		select {
		case <-connection.done:
		case <-time.After(revokeWait):
			t.Error("Trojan Process did not return after its connection was closed")
		}
	})

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.DestinationFromAddr(client.LocalAddr()),
		Tag:    "trojan-in",
	})
	go func() {
		connection.err = server.Process(ctx, net.Network_TCP, connection.server, dispatcher)
		// The proxyman worker closes the connection once Process returns.
		accepted.Close()
		close(connection.done)
	}()
	return connection
}

func requestBytes(t *testing.T, user *protocol.MemoryUser, payload string) []byte {
	t.Helper()
	var request bytesWriter
	writer := &ConnWriter{
		Writer:  &request,
		Target:  net.TCPDestination(net.LocalHostIP, 80),
		Account: user.Account.(*MemoryAccount),
	}
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	return request
}

type bytesWriter []byte

func (w *bytesWriter) Write(b []byte) (int, error) {
	*w = append(*w, b...)
	return len(b), nil
}

func (c *revokeConnection) send(t *testing.T, b []byte) {
	t.Helper()
	if _, err := c.client.Write(b); err != nil {
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
	server := newRevokeServer(t, victim, bystander)
	dispatcher := newRevokeDispatcher()

	victims := make([]*revokeConnection, 2)
	for i := range victims {
		payload := "victim-" + strconv.Itoa(i)
		victims[i] = startRevokeConnection(t, server, dispatcher)
		victims[i].send(t, requestBytes(t, victim, payload))
		receive(t, dispatcher.payloads, payload, "victim before removal")
	}
	survivor := startRevokeConnection(t, server, dispatcher)
	survivor.send(t, requestBytes(t, bystander, "bystander-0"))
	receive(t, dispatcher.payloads, "bystander-0", "bystander before removal")

	if err := server.RemoveUser(context.Background(), "victim@example.com"); err != nil {
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
	survivor.send(t, []byte("bystander-1"))
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
			server := newRevokeServer(t, victim)
			authenticated := server.validator.GetByEmail(victim.Email)
			dispatcher := newRevokeDispatcher()
			connection := startRevokeConnection(t, server, dispatcher)

			// The first read carries only the user hash. Process authenticates
			// it, then blocks reading the rest of the request header.
			request := requestBytes(t, victim, "stale")
			connection.send(t, request[:58])
			for read := range connection.server.read {
				if read == 2 {
					break
				}
			}
			if err := server.RemoveUser(context.Background(), victim.Email); err != nil {
				t.Fatal(err)
			}
			if readd {
				// The API hands a fresh MemoryUser to every AddUser; an
				// embedding program may hand back the authenticated one.
				if err := server.AddUser(context.Background(), authenticated); err != nil {
					t.Fatal(err)
				}
			}
			connection.send(t, request[58:])

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
// steps through a validator hook, which the concrete Trojan validator does
// not allow.
func TestUserChangesAreSerialized(t *testing.T) {
	victim := newRevokeUser(t, "victim@example.com")
	readded := newRevokeUser(t, "victim@example.com")
	server := newRevokeServer(t, victim)

	for _, change := range []struct {
		name string
		run  func() error
	}{
		{"RemoveUser", func() error { return server.RemoveUser(context.Background(), victim.Email) }},
		{"AddUser", func() error { return server.AddUser(context.Background(), readded) }},
	} {
		server.userMu.Lock()
		done := make(chan error, 1)
		go func() { done <- change.run() }()
		select {
		case err := <-done:
			server.userMu.Unlock()
			t.Fatalf("%s ran while another user change held the lock (err %v)", change.name, err)
		case <-time.After(100 * time.Millisecond):
		}
		server.userMu.Unlock()
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
