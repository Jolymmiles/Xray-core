package mux

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singmux"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type smuxEchoDispatcher struct {
	target   chan X.Destination
	provider session.PresenceProvider
}

func (d *smuxEchoDispatcher) PresenceProvider() session.PresenceProvider { return d.provider }

func (*smuxEchoDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, io.ErrClosedPipe
}

func (d *smuxEchoDispatcher) DispatchLink(_ context.Context, destination X.Destination, link *transport.Link) error {
	d.target <- destination
	for {
		buffers, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		if err := link.Writer.WriteMultiBuffer(buffers); err != nil {
			return err
		}
	}
}

func (*smuxEchoDispatcher) Start() error      { return nil }
func (*smuxEchoDispatcher) Close() error      { return nil }
func (*smuxEchoDispatcher) Type() interface{} { return routing.DispatcherType() }

type smuxServerDialer struct {
	server *Server
}

func (d *smuxServerDialer) DialContext(ctx context.Context, destination X.Destination) (net.Conn, error) {
	link, err := d.server.Dispatch(context.Background(), destination)
	if err != nil {
		return nil, err
	}
	return cnc.NewConnection(cnc.ConnectionInputMulti(link.Writer), cnc.ConnectionOutputMulti(link.Reader)), nil
}

func smuxTestLinkPair() (*transport.Link, *transport.Link) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: uplinkReader, Writer: downlinkWriter},
		&transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
}

func newSMUXTestClient(t *testing.T, server *Server) *singmux.Client {
	t.Helper()
	client, err := singmux.NewClient(singmux.Options{
		Dialer:         &smuxServerDialer{server: server},
		Protocol:       "smux",
		MaxConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestServerExposesUnderlyingPresenceProvider(t *testing.T) {
	provider := smuxPresenceProvider{}
	server := newServer(&smuxEchoDispatcher{provider: provider})
	if server.PresenceProvider() != provider {
		t.Fatal("mux server did not expose the underlying presence provider")
	}
}

type smuxPresenceProvider struct{}

func (smuxPresenceProvider) SnapshotPresence(context.Context) session.PresenceScope {
	return session.PresenceScope{}
}

func TestServerAcceptsSMUXTCP(t *testing.T) {
	dispatcher := &smuxEchoDispatcher{target: make(chan X.Destination, 1)}
	client := newSMUXTestClient(t, newServer(dispatcher))
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	clientLink, peerLink := smuxTestLinkPair()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- client.Dispatch(ctx, clientLink, destination) }()

	if err := peerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("xray-smux"))}); err != nil {
		t.Fatal(err)
	}
	response, err := peerLink.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(response)
	if response.String() != "xray-smux" {
		t.Fatalf("response = %q", response.String())
	}
	select {
	case target := <-dispatcher.target:
		if target != destination {
			t.Fatalf("target = %s, want %s", target, destination)
		}
	case <-ctx.Done():
		t.Fatal("dispatcher did not receive target")
	}
	cancel()
	<-errCh
}

func TestServerAcceptsSMUXUDPWithPerPacketDestination(t *testing.T) {
	dispatcher := &smuxEchoDispatcher{target: make(chan X.Destination, 1)}
	client := newSMUXTestClient(t, newServer(dispatcher))
	defaultDestination := X.UDPDestination(X.DomainAddress("default.example"), 53)
	packetDestination := X.UDPDestination(X.DomainAddress("packet.example"), 5353)
	clientLink, peerLink := smuxTestLinkPair()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- client.Dispatch(ctx, clientLink, defaultDestination) }()

	packet := buf.FromBytes([]byte("dns-query"))
	packet.UDP = &packetDestination
	if err := peerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	response, err := peerLink.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(response)
	if response.String() != "dns-query" || response[0].UDP == nil || *response[0].UDP != packetDestination {
		t.Fatalf("response = %q, destination = %#v", response.String(), response[0].UDP)
	}
	cancel()
	<-errCh
}
