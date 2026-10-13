package inbound

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	dispatcherapp "github.com/xtls/xray-core/app/dispatcher"
	outboundapp "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/mux"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

// enteringDispatcher reports when Process hands its link on.
type enteringDispatcher struct {
	routing.Dispatcher
	entered chan struct{}
}

func (d *enteringDispatcher) DispatchLink(ctx context.Context, dest X.Destination, link *transport.Link) error {
	close(d.entered)
	return d.Dispatcher.DispatchLink(ctx, dest, link)
}

// TestRemoveUserEndsAMuxCarrierWithoutRacingItsReader removes the user of a
// Mux.Cool carrier served by a real mux.Server. Process returns on the
// canceled context while the server's worker can still read through
// Process's reader; -race reports it if Process releases that reader's
// buffers.
func TestRemoveUserEndsAMuxCarrierWithoutRacingItsReader(t *testing.T) {
	validator := new(vless.MemoryValidator)
	handler := newRevokeHandler(t, validator, &revokeOutboundManager{})
	victim := newRevokeUser(t, "victim@example.com", "")
	addRevokeUsers(t, handler, victim)
	instance := new(core.Instance)
	if err := instance.AddFeature(newRevokeDispatcher()); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	server := mux.NewServer(ctx)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	dispatcher := &enteringDispatcher{Dispatcher: server, entered: make(chan struct{})}

	connection := startRevokeConnection(t, handler, dispatcher, victim, protocol.RequestCommandMux, "")
	select {
	case <-dispatcher.entered:
	case <-time.After(revokeWait):
		t.Fatal("Process did not hand the carrier to the mux server")
	}
	if err := handler.RemoveUser(context.Background(), victim.Email); err != nil {
		t.Fatal(err)
	}
	connection.requireEnded(t, "Mux.Cool carrier of the removed user")
}

// defaultHandlerManager serves one default outbound handler.
type defaultHandlerManager struct {
	revokeOutboundManager
	handler outbound.Handler
}

func (m *defaultHandlerManager) GetDefaultHandler() outbound.Handler { return m.handler }

// TestRemoveUserEndsATCPConnectionWithoutRacingItsReader removes the user of
// a plain TCP request relayed by the real dispatcher and a Freedom outbound
// to a loopback listener. The outbound's copy can still read through
// Process's reader after Process returns on the canceled context.
func TestRemoveUserEndsATCPConnectionWithoutRacingItsReader(t *testing.T) {
	validator := new(vless.MemoryValidator)
	handler := newRevokeHandler(t, validator, &revokeOutboundManager{})
	victim := newRevokeUser(t, "victim@example.com", "")
	addRevokeUsers(t, handler, victim)

	target, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan stdnet.Conn, 1)
	acceptDone := make(chan struct{})
	t.Cleanup(func() {
		target.Close()
		select {
		case <-acceptDone:
		case <-time.After(revokeWait):
			t.Error("the target's Accept did not return")
		}
		select {
		case conn := <-accepted:
			conn.Close()
		default:
		}
	})
	go func() {
		defer close(acceptDone)
		if conn, err := target.Accept(); err == nil {
			accepted <- conn
		}
	}()

	instance := new(core.Instance)
	if err := instance.AddFeature(handler.policyManager); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	proxy, err := outboundapp.NewHandler(ctx, &core.OutboundHandlerConfig{
		ProxySettings: serial.ToTypedMessage(&freedom.Config{
			FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{
				Port: uint32(target.Addr().(*stdnet.TCPAddr).Port),
			}},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := proxy.Close(); err != nil {
			t.Error(err)
		}
	})
	dispatcher := new(dispatcherapp.DefaultDispatcher)
	if err := dispatcher.Init(&dispatcherapp.Config{}, &defaultHandlerManager{handler: proxy}, nil, handler.policyManager, nil); err != nil {
		t.Fatal(err)
	}

	connection := startRevokeConnection(t, handler, dispatcher, victim, protocol.RequestCommandTCP, "")
	select {
	case upstream := <-accepted:
		t.Cleanup(func() { upstream.Close() })
	case <-time.After(revokeWait):
		t.Fatal("Freedom did not connect to the target")
	}
	if err := handler.RemoveUser(context.Background(), victim.Email); err != nil {
		t.Fatal(err)
	}
	connection.requireEnded(t, "TCP connection of the removed user")
}
