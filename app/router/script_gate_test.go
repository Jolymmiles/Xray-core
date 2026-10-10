package router

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
)

// Upstream's script tests build instances through core.New, where the fork
// rejects scripts (docs/FORK.md); this package's tests lift the gate.
func init() { xlua.ScriptsEnabled = true }

// The fork ships Lua scripts disabled: an instance whose routing config names
// a script must not be created at all, so nothing starts and no connection is
// routed by the JSON rules in its place.
func TestCoreRejectsRoutingScriptWhileScriptsDisabled(t *testing.T) {
	config := &core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&Config{Script: writeRouteScript(t, `function HandleRoute() return "direct" end`)}),
	}}

	xlua.ScriptsEnabled = false
	t.Cleanup(func() { xlua.ScriptsEnabled = true })
	instance, err := core.New(config)
	if err == nil {
		instance.Close()
		t.Fatal("core.New accepted a routing script while scripts are disabled")
	}
	if !strings.Contains(err.Error(), xlua.ErrScriptsDisabled.Error()) {
		t.Fatalf("core.New error = %v, want %q", err, xlua.ErrScriptsDisabled)
	}

	// Control: the same config is valid once scripts are enabled.
	xlua.ScriptsEnabled = true
	instance, err = core.New(config)
	if err != nil {
		t.Fatalf("core.New with scripts enabled: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
}
