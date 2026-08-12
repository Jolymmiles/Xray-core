package dispatcher

import (
	"context"
	"net/netip"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestDirectDispatchLinkActivatesTrustedPresenceUntilContextTerminal(t *testing.T) {
	dispatcher, manager := newDirectPresenceDispatcher(t, &statelessOutbound{})
	ctx, cancel := context.WithCancel(directPresenceContext(session.PresenceModeContext))
	link := directPresenceLink()

	if err := dispatcher.DispatchLink(ctx, net.TCPDestination(net.DomainAddress("example.com"), 443), link); err != nil {
		t.Fatal(err)
	}
	assertOnlineMap(t, manager, directPresenceMetric, 1, "192.0.2.44")
	common.Close(link.Writer)
	assertOnlineMap(t, manager, directPresenceMetric, 1, "192.0.2.44")
	cancel()
	waitOnlineCount(t, manager, directPresenceMetric, 0)
}

func TestDirectDispatchActivatesAfterRouteAcceptance(t *testing.T) {
	dispatcher, manager := newDirectPresenceDispatcher(t, &statelessOutbound{})
	ctx, cancel := context.WithCancel(directPresenceContext(session.PresenceModeContext))
	defer cancel()
	link, err := dispatcher.Dispatch(ctx, net.TCPDestination(net.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(link.Reader)
	defer common.Interrupt(link.Writer)
	waitOnlineCount(t, manager, directPresenceMetric, 1)
	assertOnlineMap(t, manager, directPresenceMetric, 1, "192.0.2.44")
	cancel()
	waitOnlineCount(t, manager, directPresenceMetric, 0)
}

func TestDirectPresenceDoesNotActivateWithoutAcceptedRoute(t *testing.T) {
	dispatcher, manager := newDirectPresenceDispatcher(t, nil)
	ctx, cancel := context.WithCancel(directPresenceContext(session.PresenceModeContext))
	defer cancel()
	if err := dispatcher.DispatchLink(ctx, net.TCPDestination(net.DomainAddress("example.com"), 443), directPresenceLink()); err != nil {
		t.Fatal(err)
	}
	if onlineMap := manager.GetOnlineMap(directPresenceMetric); onlineMap != nil && onlineMap.Count() != 0 {
		t.Fatalf("failed route published online count %d", onlineMap.Count())
	}
}

func TestDirectPresenceModesSuppressDispatcherOwnership(t *testing.T) {
	for name, mode := range map[string]session.PresenceMode{"External": session.PresenceModeExternal, "Untracked": session.PresenceModeUntracked} {
		t.Run(name, func(t *testing.T) {
			dispatcher, manager := newDirectPresenceDispatcher(t, &statelessOutbound{})
			ctx, cancel := context.WithCancel(directPresenceContext(mode))
			defer cancel()
			if err := dispatcher.DispatchLink(ctx, net.TCPDestination(net.DomainAddress("example.com"), 443), directPresenceLink()); err != nil {
				t.Fatal(err)
			}
			if onlineMap := manager.GetOnlineMap(directPresenceMetric); onlineMap != nil && onlineMap.Count() != 0 {
				t.Fatalf("mode %d published online count %d", mode, onlineMap.Count())
			}
		})
	}
}

func directPresenceLink() *transport.Link {
	reader, writer := pipe.New()
	return &transport.Link{Reader: reader, Writer: writer}
}

const directPresenceMetric = "user>>>alice@example.com>>>online"

func newDirectPresenceDispatcher(t *testing.T, handler outbound.Handler) (*DefaultDispatcher, *appstats.Manager) {
	t.Helper()
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(nil, &fixedOutboundManager{handler: handler}, routing.DefaultRouter{}, &presenceTestPolicy{online: true}, manager); err != nil {
		t.Fatal(err)
	}
	return dispatcher, manager
}

func directPresenceContext(mode session.PresenceMode) context.Context {
	ctx := session.ContextWithConnection(context.Background(), 1, session.Inbound{
		Source:       net.TCPDestination(net.ParseAddress("198.51.100.99"), 12345),
		PhysicalPeer: netip.MustParseAddr("192.0.2.44"),
		Tag:          "inbound-a",
		Name:         "vless",
		User:         &protocol.MemoryUser{Email: "alice@example.com", Level: 7},
	}, session.Outbound{}, session.Content{})
	return session.ContextWithPresenceMode(ctx, mode)
}

func waitOnlineCount(t *testing.T, manager *appstats.Manager, metric string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if onlineMap := manager.GetOnlineMap(metric); onlineMap != nil && onlineMap.Count() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	onlineMap := manager.GetOnlineMap(metric)
	if onlineMap == nil {
		t.Fatalf("online map %q not found", metric)
	}
	t.Fatalf("online count = %d, want %d", onlineMap.Count(), want)
}
