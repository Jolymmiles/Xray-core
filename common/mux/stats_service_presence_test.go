package mux

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	presencefixture "github.com/xtls/xray-core/testing/presence"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestLegacyMuxStatsServiceTracksTCPAndPacketUDP(t *testing.T) {
	for _, test := range []struct {
		name        string
		destination X.Destination
	}{
		{name: "TCP", destination: X.TCPDestination(X.DomainAddress("example.com"), 443)},
		{name: "packet UDP", destination: X.UDPDestination(X.DomainAddress("example.com"), 53)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := presencefixture.New(t)
			dispatcher := &statsServiceMuxDispatcher{provider: &fixedPresenceProvider{scope: fixture.Scope(t, "mux@example.com", "192.0.2.44")}, mode: make(chan session.PresenceMode, 1)}
			serverLink, clientLink := muxPresenceLinkPair()
			server, err := NewServerWorker(context.Background(), dispatcher, serverLink)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := NewClientWorker(*clientLink, ClientStrategy{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			fixture.AssertIPs(t, "mux@example.com")

			requestReader, requestWriter := pipe.New(pipe.WithoutSizeLimit())
			_, responseWriter := pipe.New(pipe.WithoutSizeLimit())
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: test.destination}})
			if !client.Dispatch(ctx, &transport.Link{Reader: requestReader, Writer: responseWriter}) {
				t.Fatal("client session was rejected")
			}
			if err := requestWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))}); err != nil {
				t.Fatal(err)
			}
			if mode := <-dispatcher.mode; mode != session.PresenceModeExternal {
				t.Fatalf("server dispatch mode = %d, want External", mode)
			}
			fixture.WaitIPs(t, "mux@example.com", "192.0.2.44")
			if err := requestWriter.Close(); err != nil {
				t.Fatal(err)
			}
			fixture.WaitIPs(t, "mux@example.com")
		})
	}
}

func TestXUDPStatsServiceTracksAttachRebindCacheAndExpiry(t *testing.T) {
	fixture := presencefixture.New(t)
	runtime := newRuntime()
	defer runtime.Close()
	backendReader, backendWriter := pipe.New(pipe.WithoutSizeLimit())
	key := xudpRuntimeKey{principal: [32]byte{1}, globalID: [8]byte{2}}
	flow := newXUDPFlow(runtime, key, X.UDPDestination(X.DomainAddress("example.com"), 53), &transport.Link{Reader: backendReader, Writer: backendWriter})
	runtime.mu.Lock()
	runtime.flows[key] = flow
	runtime.mu.Unlock()
	registry := newSessionRegistry()
	sink := runtime.newResponseSink(buf.Discard)

	first, err := flow.attach(registry.reserve(1), fixture.Scope(t, "xudp@example.com", "192.0.2.10"), sink)
	if err != nil {
		t.Fatal(err)
	}
	fixture.AssertIPs(t, "xudp@example.com", "192.0.2.10")
	second, err := flow.attach(registry.reserve(2), fixture.Scope(t, "xudp@example.com", "198.51.100.20"), sink)
	if err != nil {
		t.Fatal(err)
	}
	fixture.AssertIPs(t, "xudp@example.com", "198.51.100.20")
	if err := first.Close(false); err != nil {
		t.Fatal(err)
	}
	fixture.AssertIPs(t, "xudp@example.com", "198.51.100.20")
	if err := second.Close(false); err != nil {
		t.Fatal(err)
	}
	fixture.AssertIPs(t, "xudp@example.com")
	if runtimeFlowCount(runtime) != 1 {
		t.Fatalf("detached cache flows = %d, want 1", runtimeFlowCount(runtime))
	}
	runtime.expire(time.Now().Add(2 * runtime.expiry))
	fixture.AssertIPs(t, "xudp@example.com")
	if runtimeFlowCount(runtime) != 0 {
		t.Fatalf("expired cache flows = %d, want 0", runtimeFlowCount(runtime))
	}
}

type fixedPresenceProvider struct{ scope session.PresenceScope }

func (p *fixedPresenceProvider) SnapshotPresence(context.Context) session.PresenceScope {
	return p.scope
}

type statsServiceMuxDispatcher struct {
	provider session.PresenceProvider
	mode     chan session.PresenceMode
}

func (d *statsServiceMuxDispatcher) PresenceProvider() session.PresenceProvider { return d.provider }

func (d *statsServiceMuxDispatcher) Dispatch(ctx context.Context, _ X.Destination) (*transport.Link, error) {
	d.mode <- session.PresenceModeFromContext(ctx)
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: reader, Writer: writer}, nil
}

func (*statsServiceMuxDispatcher) DispatchLink(context.Context, X.Destination, *transport.Link) error {
	return errors.New("unexpected DispatchLink")
}
func (*statsServiceMuxDispatcher) Start() error      { return nil }
func (*statsServiceMuxDispatcher) Close() error      { return nil }
func (*statsServiceMuxDispatcher) Type() interface{} { return routing.DispatcherType() }
