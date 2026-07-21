package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	F "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func TestNewHandlerCreatesSingMuxClient(t *testing.T) {
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&policy.Config{}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	instance.AddFeature(F.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})

	handler, err := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag: "smux-out",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
			SmuxSettings: &proxyman.SmuxConfig{
				Enabled:        true,
				Protocol:       "smux",
				MaxConnections: 2,
				OnlyTcp:        true,
			},
		}),
		ProxySettings: serial.ToTypedMessage(&freedom.Config{
			FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })

	concrete := handler.(*Handler)
	if concrete.smux == nil {
		t.Fatal("SMUX client was not created")
	}
	if concrete.smux.ShouldHandle(X.Network_UDP) {
		t.Fatal("UDP must bypass SMUX when onlyTcp is enabled")
	}
}
