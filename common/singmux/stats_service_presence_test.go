package singmux

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/features/routing"
	presencefixture "github.com/xtls/xray-core/testing/presence"
	"github.com/xtls/xray-core/transport"
)

func TestSMUXAndH2MUXStatsServiceTrackDataStreams(t *testing.T) {
	for _, protocol := range []string{"smux", "h2mux"} {
		t.Run(protocol, func(t *testing.T) {
			fixture := presencefixture.New(t)
			dispatcher := &statsServiceDispatcher{
				provider:   &statsServiceProvider{scope: fixture.Scope(t, protocol+"@example.com", "192.0.2.44")},
				dispatched: make(chan struct{}, 1),
			}
			var stream io.Closer
			var closeCarrier func()
			if protocol == "smux" {
				var carrier *localsmux.Session
				carrier, closeCarrier = startStatsServiceSMUX(t, dispatcher)
				stream = openPresenceSMUXStream(t, carrier)
			} else {
				client, closeH2 := startH2MuxServiceWithContext(t, NewService(dispatcher), []byte{0, 2}, func(net.Conn) context.Context { return context.Background() })
				closeCarrier = closeH2
				response, bodyWriter := openH2MuxStream(t, client)
				if err := writeStreamRequest(bodyWriter, 0, X.TCPDestination(X.DomainAddress("example.com"), 443)); err != nil {
					t.Fatal(err)
				}
				if err := readStreamResponse(response.Body); err != nil {
					t.Fatal(err)
				}
				stream = &h2PresenceStream{request: bodyWriter, response: response.Body}
			}
			defer closeCarrier()
			select {
			case <-dispatcher.dispatched:
			case <-time.After(time.Second):
				t.Fatal("data stream did not reach dispatcher")
			}
			fixture.AssertIPs(t, protocol+"@example.com", "192.0.2.44")
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			fixture.WaitIPs(t, protocol+"@example.com")
		})
	}
}

func startStatsServiceSMUX(t *testing.T, dispatcher *statsServiceDispatcher) (*localsmux.Session, func()) {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- NewService(dispatcher).NewConnection(ctx, serverConnection) }()
	if err := writeCarrierRequest(clientConnection, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	carrier, err := localsmux.Client(clientConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	return carrier, func() {
		_ = carrier.Close()
		cancel()
		_ = clientConnection.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Error("SMUX StatsService carrier did not stop")
		}
	}
}

type statsServiceProvider struct{ scope session.PresenceScope }

func (p *statsServiceProvider) SnapshotPresence(context.Context) session.PresenceScope {
	return p.scope
}

type statsServiceDispatcher struct {
	provider   session.PresenceProvider
	dispatched chan struct{}
}

func (d *statsServiceDispatcher) PresenceProvider() session.PresenceProvider { return d.provider }
func (*statsServiceDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, context.Canceled
}

func (d *statsServiceDispatcher) DispatchLink(ctx context.Context, _ X.Destination, link *transport.Link) error {
	if session.PresenceModeFromContext(ctx) != session.PresenceModeExternal {
		return context.Canceled
	}
	d.dispatched <- struct{}{}
	_, err := link.Reader.ReadMultiBuffer()
	return err
}
func (*statsServiceDispatcher) Start() error      { return nil }
func (*statsServiceDispatcher) Close() error      { return nil }
func (*statsServiceDispatcher) Type() interface{} { return routing.DispatcherType() }

type h2PresenceStream struct {
	request  io.Closer
	response io.Closer
}

func (s *h2PresenceStream) Close() error {
	first := s.request.Close()
	second := s.response.Close()
	if first != nil {
		return first
	}
	return second
}
