package dns_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
)

// The fork ships Lua scripts disabled (docs/FORK.md): an instance whose DNS
// config names a script must not be created at all.
func TestCoreRejectsDNSScriptWhileScriptsDisabled(t *testing.T) {
	script := filepath.Join(t.TempDir(), "dns.lua")
	if err := os.WriteFile(script, []byte(`function HandleDNSQuery() return nil, 0 end`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&Config{Script: script}),
	}}

	enabled := xlua.ScriptsEnabled
	t.Cleanup(func() { xlua.ScriptsEnabled = enabled })
	xlua.ScriptsEnabled = false
	instance, err := core.New(config)
	if err == nil {
		instance.Close()
		t.Fatal("core.New accepted a DNS script while scripts are disabled")
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
