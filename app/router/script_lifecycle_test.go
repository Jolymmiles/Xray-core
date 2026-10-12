package router

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// TestRouterRoutesByRulesBeforeScriptStarts routes before Start. The inbound
// manager starts before the router, so its first connections and the TUN DNS
// takeover probe can be routed while the script's pool does not run yet; they
// take the JSON rules (docs/FORK.md), and the script decides from Start on.
func TestRouterRoutesByRulesBeforeScriptStarts(t *testing.T) {
	for _, fast := range []bool{false, true} {
		name := "PickRoute"
		if fast {
			name = "PickRouteTag"
		}
		t.Run(name, func(t *testing.T) {
			r := new(Router)
			config := &Config{
				Script: writeRouteScript(t, `function HandleRoute() return "lua-out" end`),
				Rule: []*RoutingRule{{
					TargetTag: &RoutingRule_Tag{Tag: "json-out"},
					Networks:  []net.Network{net.Network_TCP},
				}},
			}
			if err := r.Init(context.Background(), config, nil, &luaRouteOutboundManager{}, nil); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			route := func() (tag string, err error) {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("routing panicked: %v", p)
					}
				}()
				if fast {
					tag, _, err = r.PickRouteTag(newLuaRouteTestContext())
					return tag, err
				}
				picked, err := r.PickRoute(newLuaRouteTestContext())
				if picked != nil {
					tag = picked.GetOutboundTag()
				}
				return tag, err
			}
			if tag, err := route(); err != nil || tag != "json-out" {
				t.Fatalf("before Start the route is %q, %v; want the JSON rule's json-out", tag, err)
			}
			if r.NeedsSniffingAttributes() {
				t.Error("before Start a script that does not run asks for HTTP attributes")
			}
			if err := r.Start(); err != nil {
				t.Fatal(err)
			}
			if tag, err := route(); err != nil || tag != "lua-out" {
				t.Fatalf("after Start the route is %q, %v; want the script's lua-out", tag, err)
			}
		})
	}
}
