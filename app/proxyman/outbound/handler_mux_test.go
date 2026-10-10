package outbound

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	F "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func newMuxTestContext(t *testing.T) context.Context {
	t.Helper()
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&policy.Config{}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	instance.AddFeature(F.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
}

func muxStrategy(t *testing.T, manager *mux.ClientManager) mux.ClientStrategy {
	t.Helper()
	picker, ok := manager.Picker.(*mux.IncrementalWorkerPicker)
	if !ok {
		t.Fatalf("mux picker = %T, want *mux.IncrementalWorkerPicker", manager.Picker)
	}
	factory, ok := picker.Factory.(*mux.DialingWorkerFactory)
	if !ok {
		t.Fatalf("mux worker factory = %T, want *mux.DialingWorkerFactory", picker.Factory)
	}
	return factory.Strategy
}

// maxReuseTimes is the lifetime session budget of a carrier in the main
// Mux.Cool pool. That pool also carries UDP when no separate XUDP pool is
// configured; the XUDP pool keeps its budget of 128.
func TestNewHandlerAppliesMuxMaxReuseTimes(t *testing.T) {
	for _, test := range []struct {
		name            string
		maxReuseTimes   int32
		xudpConcurrency int32
		want            uint32
	}{
		{"default", 0, 4, 128},
		{"one", 1, 4, 1},
		{"above the default", 129, 4, 129},
		{"ceiling", 60000, 4, 60000},
		{"UDP through the main pool", 7, 0, 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(newMuxTestContext(t), &core.OutboundHandlerConfig{
				Tag: "mux-out",
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					MultiplexSettings: &proxyman.MultiplexingConfig{
						Enabled:         true,
						Concurrency:     8,
						XudpConcurrency: test.xudpConcurrency,
						MaxReuseTimes:   test.maxReuseTimes,
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
			if got := muxStrategy(t, concrete.mux); got.MaxConnection != test.want || got.MaxConcurrency != 8 {
				t.Fatalf("mux strategy = %+v, want MaxConnection %d and MaxConcurrency 8", got, test.want)
			}
			if test.xudpConcurrency == 0 {
				if concrete.xudp != nil {
					t.Fatal("UDP must use the main pool without xudpConcurrency")
				}
				return
			}
			if got := muxStrategy(t, concrete.xudp); got.MaxConnection != 128 {
				t.Fatalf("XUDP strategy = %+v, want MaxConnection 128", got)
			}
		})
	}
}

// An out-of-range budget fails before the proxy is built, whether mux is
// enabled or not: a protobuf config or the HandlerService API never passes
// through the JSON check.
func TestNewHandlerRejectsInvalidMuxMaxReuseTimes(t *testing.T) {
	for _, settings := range []*proxyman.MultiplexingConfig{
		{Enabled: true, MaxReuseTimes: -1},
		{Enabled: true, MaxReuseTimes: 60001},
		{Enabled: false, MaxReuseTimes: -1},
	} {
		_, err := NewHandler(newMuxTestContext(t), &core.OutboundHandlerConfig{
			Tag:            "mux-out",
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{MultiplexSettings: settings}),
			// Building this proxy fails, so only an earlier check names the budget.
			ProxySettings: &serial.TypedMessage{Type: "xray.test.NotRegistered"},
		})
		if err == nil || !strings.Contains(err.Error(), "maxReuseTimes") {
			t.Errorf("NewHandler(%+v) error = %v, want a maxReuseTimes error", settings, err)
		}
	}
}
