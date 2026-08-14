package trojan_test

import (
	"context"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	. "github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func toAccount(a *Account) protocol.Account {
	account, err := a.AsAccount()
	common.Must(err)
	return account
}

func TestTCPRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Email: "love@example.com",
		Account: toAccount(&Account{
			Password: "password",
		}),
	}
	payload := []byte("test string")
	data := buf.New()
	common.Must2(data.Write(payload))

	buffer := buf.New()
	defer buffer.Release()

	destination := net.Destination{Network: net.Network_TCP, Address: net.LocalHostIP, Port: 1234}
	writer := &ConnWriter{Writer: buffer, Target: destination, Account: user.Account.(*MemoryAccount)}
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{data}))

	reader := &ConnReader{Reader: buffer}
	common.Must(reader.ParseHeader())

	if r := cmp.Diff(reader.Target, destination); r != "" {
		t.Error("destination: ", r)
	}

	decodedData, err := reader.ReadMultiBuffer()
	common.Must(err)
	if r := cmp.Diff(decodedData[0].Bytes(), payload); r != "" {
		t.Error("data: ", r)
	}
}

type trojanTestConn struct {
	stdnet.Conn
	remote stdnet.Addr
	local  stdnet.Addr
}

func (c *trojanTestConn) RemoteAddr() stdnet.Addr { return c.remote }
func (c *trojanTestConn) LocalAddr() stdnet.Addr  { return c.local }

type trojanPresenceDispatcher struct {
	provider session.PresenceProvider
	subject  chan session.PresenceSubject
}

func (*trojanPresenceDispatcher) Type() interface{}                            { return routing.DispatcherType() }
func (*trojanPresenceDispatcher) Start() error                                 { return nil }
func (*trojanPresenceDispatcher) Close() error                                 { return nil }
func (d *trojanPresenceDispatcher) PresenceProvider() session.PresenceProvider { return d.provider }
func (d *trojanPresenceDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.subject <- d.provider.SnapshotPresence(ctx).Subject()
	reader, writer := pipe.New()
	_ = writer.Close()
	return &transport.Link{Reader: reader, Writer: writer}, nil
}

func (*trojanPresenceDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

type trojanPresenceProvider struct{}

func (trojanPresenceProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	inbound := session.InboundFromContext(ctx)
	return session.NewPresenceScope(session.PresenceSubject{
		Email: inbound.User.Email, Level: inbound.User.Level, IP: inbound.PhysicalPeer,
	}, trojanPresenceTracker{})
}

type trojanPresenceTracker struct{}

func (trojanPresenceTracker) Prepare(session.PresenceSubject) session.PresenceReservation { return nil }

func TestServerSnapshotsAuthenticatedUserAndPhysicalPeer(t *testing.T) {
	configUser := &protocol.User{
		Email: "alice@example.com", Level: 7,
		Account: serial.ToTypedMessage(&Account{Password: "password"}),
	}
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&policy.Config{})}})
	common.Must(err)
	t.Cleanup(func() { _ = instance.Close() })
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = context.WithValue(ctx, "cone", false)
	server, err := NewServer(ctx, &ServerConfig{Users: []*protocol.User{configUser}})
	common.Must(err)

	serverPipe, clientConn := stdnet.Pipe()
	serverConn := &trojanTestConn{
		Conn:   serverPipe,
		remote: &stdnet.TCPAddr{IP: stdnet.ParseIP("198.51.100.7"), Port: 12345},
		local:  &stdnet.TCPAddr{IP: stdnet.ParseIP("203.0.113.10"), Port: 443},
	}
	defer clientConn.Close()
	physicalPeer := netip.MustParseAddr("192.0.2.9")
	ctx = session.ContextWithConnection(ctx, 1, session.Inbound{
		Source:       net.TCPDestination(net.ParseAddress("198.51.100.7"), 12345),
		PhysicalPeer: physicalPeer,
	}, session.Outbound{}, session.Content{})
	provider := trojanPresenceProvider{}
	dispatcher := &trojanPresenceDispatcher{provider: provider, subject: make(chan session.PresenceSubject, 1)}
	processDone := make(chan error, 1)
	go func() { processDone <- server.Process(ctx, net.Network_TCP, serverConn, dispatcher) }()
	memoryUser, err := configUser.ToMemoryUser()
	common.Must(err)
	request := &ConnWriter{Writer: clientConn, Target: net.TCPDestination(net.DomainAddress("example.com"), 443), Account: memoryUser.Account.(*MemoryAccount)}
	_, err = request.Write([]byte("x"))
	common.Must(err)

	select {
	case subject := <-dispatcher.subject:
		if subject.Email != configUser.Email || subject.Level != configUser.Level || subject.IP != physicalPeer {
			t.Fatalf("Trojan authenticated snapshot = %+v", subject)
		}
	case <-time.After(time.Second):
		t.Fatal("Trojan request was not authenticated and dispatched")
	}
	_ = clientConn.Close()
	select {
	case <-processDone:
	case <-time.After(time.Second):
		t.Fatal("Trojan Process did not stop after client close")
	}
}

func TestUDPRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Email: "love@example.com",
		Account: toAccount(&Account{
			Password: "password",
		}),
	}
	payload := []byte("test string")
	data := buf.New()
	common.Must2(data.Write(payload))

	buffer := buf.New()
	defer buffer.Release()

	destination := net.Destination{Network: net.Network_UDP, Address: net.LocalHostIP, Port: 1234}
	writer := &PacketWriter{Writer: &ConnWriter{Writer: buffer, Target: destination, Account: user.Account.(*MemoryAccount)}, Target: destination}
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{data}))

	connReader := &ConnReader{Reader: buffer}
	common.Must(connReader.ParseHeader())

	packetReader := &PacketReader{Reader: connReader}
	mb, err := packetReader.ReadMultiBuffer()
	common.Must(err)

	if mb.IsEmpty() {
		t.Error("no request data")
	}

	mb2, b := buf.SplitFirst(mb)
	defer buf.ReleaseMulti(mb2)

	dest := *b.UDP
	if r := cmp.Diff(dest, destination); r != "" {
		t.Error("destination: ", r)
	}

	if r := cmp.Diff(b.Bytes(), payload); r != "" {
		t.Error("data: ", r)
	}
}
