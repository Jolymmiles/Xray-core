package inbound

import (
	"context"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	corenet "github.com/xtls/xray-core/common/net"
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

type vmessPresenceConn struct {
	stdnet.Conn
	remote stdnet.Addr
	local  stdnet.Addr
}

func (c *vmessPresenceConn) RemoteAddr() stdnet.Addr { return c.remote }
func (c *vmessPresenceConn) LocalAddr() stdnet.Addr  { return c.local }

type vmessPresenceDispatcher struct {
	provider session.PresenceProvider
	subject  chan session.PresenceSubject
}

func (*vmessPresenceDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*vmessPresenceDispatcher) Start() error      { return nil }
func (*vmessPresenceDispatcher) Close() error      { return nil }
func (d *vmessPresenceDispatcher) PresenceProvider() session.PresenceProvider {
	return d.provider
}

func (d *vmessPresenceDispatcher) Dispatch(ctx context.Context, _ corenet.Destination) (*transport.Link, error) {
	d.subject <- d.provider.SnapshotPresence(ctx).Subject()
	responseReader, responseWriter := pipe.New()
	_ = responseWriter.Close()
	requestReader, requestWriter := pipe.New()
	_ = requestReader
	return &transport.Link{Reader: responseReader, Writer: requestWriter}, nil
}

func (*vmessPresenceDispatcher) DispatchLink(context.Context, corenet.Destination, *transport.Link) error {
	return nil
}

type vmessPresenceProvider struct{}

func (vmessPresenceProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	inbound := session.InboundFromContext(ctx)
	return session.NewPresenceScope(session.PresenceSubject{
		Email: inbound.User.Email, Level: inbound.User.Level, IP: inbound.PhysicalPeer,
	}, vmessPresenceTracker{})
}

type vmessPresenceTracker struct{}

func (vmessPresenceTracker) Prepare(session.PresenceSubject) session.PresenceReservation { return nil }

func TestHandlerSnapshotsAuthenticatedUserAndPhysicalPeer(t *testing.T) {
	id := uuid.New()
	account, err := (&vmess.Account{
		Id:               id.String(),
		SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM},
	}).AsAccount()
	common.Must(err)
	user := &protocol.MemoryUser{Email: "alice@example.com", Level: 7, Account: account}
	clients := vmess.NewTimedUserValidator()
	common.Must(clients.Add(user))
	handler := &Handler{
		policyManager:  policy.DefaultManager{},
		clients:        clients,
		usersByEmail:   newUserByEmail(&DefaultConfig{}),
		sessionHistory: encoding.NewSessionHistory(),
	}
	t.Cleanup(func() { _ = handler.Close() })

	serverPipe, clientConn := stdnet.Pipe()
	serverConn := &vmessPresenceConn{
		Conn:   serverPipe,
		remote: &stdnet.TCPAddr{IP: stdnet.ParseIP("198.51.100.7"), Port: 12345},
		local:  &stdnet.TCPAddr{IP: stdnet.ParseIP("203.0.113.10"), Port: 443},
	}
	physicalPeer := netip.MustParseAddr("192.0.2.9")
	ctx := session.ContextWithConnection(context.Background(), 1, session.Inbound{
		Source:       corenet.TCPDestination(corenet.ParseAddress("198.51.100.7"), 12345),
		PhysicalPeer: physicalPeer,
	}, session.Outbound{}, session.Content{})
	dispatcher := &vmessPresenceDispatcher{provider: vmessPresenceProvider{}, subject: make(chan session.PresenceSubject, 1)}
	processDone := make(chan error, 1)
	go func() { processDone <- handler.Process(ctx, corenet.Network_TCP, serverConn, dispatcher) }()

	request := &protocol.RequestHeader{
		Version: 1, User: user, Command: protocol.RequestCommandTCP,
		Address: corenet.DomainAddress("example.com"), Port: 443,
		Security: protocol.SecurityType_AES128_GCM,
		Option:   protocol.RequestOptionChunkStream,
	}
	clientSession := encoding.NewClientSession(context.Background(), 0)
	common.Must(clientSession.EncodeRequestHeader(request, clientConn))
	bodyWriter, err := clientSession.EncodeRequestBody(request, clientConn)
	common.Must(err)
	common.Must(bodyWriter.WriteMultiBuffer(buf.MultiBuffer{}))

	select {
	case subject := <-dispatcher.subject:
		if subject.Email != user.Email || subject.Level != user.Level || subject.IP != physicalPeer {
			t.Fatalf("VMess authenticated snapshot = %+v", subject)
		}
	case <-time.After(time.Second):
		t.Fatal("VMess request was not authenticated and dispatched")
	}
	_ = clientConn.Close()
	select {
	case <-processDone:
	case <-time.After(time.Second):
		t.Fatal("VMess Process did not stop after client close")
	}
}
