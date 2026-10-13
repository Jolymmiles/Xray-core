package router

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

// The dispatcher routes through PickRouteTag, the fork's allocation-free
// route picker, not through PickRoute. A routing script must decide both, and
// a JSON rule that also matches must not win on the dispatcher's path.
func TestRouterScriptDecidesPickRouteTag(t *testing.T) {
	d := &luaRouteDNSClient{lookup: func(string, featureDNS.IPOption) ([]net.IP, uint32, error) {
		t.Error("script routing resolved DNS")
		return nil, 0, nil
	}}
	script := `
function HandleRoute(ctx, inbound)
    if inbound == "routed" then return "lua-out", "lua-rule" end
    if inbound == "failed" then return nil, nil, "blocked" end
    return nil
end
`
	r := startLuaRouter(t, script, d, &Config{
		Rule: []*RoutingRule{{
			TargetTag: &RoutingRule_Tag{Tag: "json-out"},
			Networks:  []net.Network{net.Network_TCP},
		}},
	})

	for _, tc := range []struct {
		inbound, wantTag, wantRule string
		wantErr                    error
		wantMessage                string
	}{
		{inbound: "routed", wantTag: "lua-out", wantRule: "lua-rule"},
		{inbound: "unmatched", wantErr: common.ErrNoClue},
		{inbound: "failed", wantMessage: "blocked"},
	} {
		t.Run(tc.inbound, func(t *testing.T) {
			ctx := newLuaRouteTestContext()
			ctx.Inbound.Tag = tc.inbound
			tag, rule, err := r.PickRouteTag(ctx)
			switch {
			case tc.wantErr != nil:
				if err != tc.wantErr {
					t.Fatalf("PickRouteTag error = %v, want %v", err, tc.wantErr)
				}
			case tc.wantMessage != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
					t.Fatalf("PickRouteTag error = %v, want %q", err, tc.wantMessage)
				}
			case err != nil:
				t.Fatal(err)
			}
			if tag != tc.wantTag || rule != tc.wantRule {
				t.Fatalf("PickRouteTag = %q, %q; want %q, %q", tag, rule, tc.wantTag, tc.wantRule)
			}

			route, routeErr := r.PickRoute(ctx)
			routeTag, routeRule := "", ""
			if route != nil {
				routeTag, routeRule = route.GetOutboundTag(), route.GetRuleTag()
			}
			if routeTag != tag || routeRule != rule || (routeErr == nil) != (err == nil) {
				t.Fatalf("PickRoute = %q, %q, %v; PickRouteTag = %q, %q, %v", routeTag, routeRule, routeErr, tag, rule, err)
			}
		})
	}
}

// A routing script can read HTTP attributes through ctx:GetAttributes(), so
// the dispatcher must keep collecting them whatever the JSON rules need.
func TestRouterScriptNeedsSniffingAttributes(t *testing.T) {
	config := func() *Config {
		return &Config{Rule: []*RoutingRule{{
			TargetTag: &RoutingRule_Tag{Tag: "json-out"},
			Networks:  []net.Network{net.Network_TCP},
		}}}
	}

	plain := new(Router)
	if err := plain.Init(t.Context(), config(), nil, &luaRouteOutboundManager{}, nil); err != nil {
		t.Fatal(err)
	}
	if plain.NeedsSniffingAttributes() {
		t.Fatal("rules without attributes report that they need sniffed attributes")
	}

	scripted := startLuaRouter(t, `function HandleRoute(ctx) return ctx:GetAttributes()["key"] end`, nil, config())
	if !scripted.NeedsSniffingAttributes() {
		t.Fatal("a router with a routing script lets the dispatcher skip sniffed attributes")
	}
}
