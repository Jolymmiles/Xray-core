package dispatcher_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	presencefixture "github.com/xtls/xray-core/testing/presence"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

func TestDirectTCPAndUDPStatsServiceTrackAcceptedRequests(t *testing.T) {
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		t.Run(network.String(), func(t *testing.T) {
			fixture := presencefixture.New(t)
			owner := new(dispatcher.DefaultDispatcher)
			if err := owner.Init(nil, &fixedOutboundManager{handler: &acceptedOutbound{}}, routing.DefaultRouter{}, onlinePolicy{}, fixture.Manager()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(session.ContextWithInbound(context.Background(), &session.Inbound{
				PhysicalPeer: netip.MustParseAddr("192.0.2.44"),
				Tag:          "direct-inbound",
				Name:         "vless",
				User:         &protocol.MemoryUser{Email: "direct@example.com", Level: 7, Account: directAccount{}},
			}))
			destination := net.Destination{Network: network, Address: net.DomainAddress("example.com"), Port: 443}
			link := directLink()
			if err := owner.DispatchLink(ctx, destination, link); err != nil {
				t.Fatal(err)
			}
			fixture.WaitIPs(t, "direct@example.com", "192.0.2.44")
			cancel()
			fixture.WaitIPs(t, "direct@example.com")
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		})
	}
}

type onlinePolicy struct{}

func (onlinePolicy) Type() any                { return policy.ManagerType() }
func (onlinePolicy) Start() error             { return nil }
func (onlinePolicy) Close() error             { return nil }
func (onlinePolicy) ForSystem() policy.System { return policy.System{} }
func (onlinePolicy) ForLevel(uint32) policy.Session {
	return policy.Session{Stats: policy.Stats{UserOnline: true}}
}

type acceptedOutbound struct{}

func (*acceptedOutbound) Dispatch(context.Context, *transport.Link) {}
func (*acceptedOutbound) Tag() string                               { return "accepted" }
func (*acceptedOutbound) Start() error                              { return nil }
func (*acceptedOutbound) Close() error                              { return nil }
func (*acceptedOutbound) SenderSettings() *serial.TypedMessage      { return nil }
func (*acceptedOutbound) ProxySettings() *serial.TypedMessage       { return nil }

type fixedOutboundManager struct {
	outbound.Manager
	handler outbound.Handler
}

func (m *fixedOutboundManager) GetDefaultHandler() outbound.Handler { return m.handler }
func (m *fixedOutboundManager) GetHandler(string) outbound.Handler  { return m.handler }

func directLink() *transport.Link {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: reader, Writer: writer}
}

type directAccount struct{}

func (directAccount) Equals(protocol.Account) bool { return true }
func (directAccount) ToProto() proto.Message       { return &protocol.User{Email: "direct@example.com"} }
