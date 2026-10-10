package conf_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/core"
	. "github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/proxy/freedom"
)

// The fork ships upstream's Lua scripts disabled (docs/FORK.md). Nothing in
// this test binary touches the gate, so these JSON configs meet the shipping
// default; the router and DNS tests only check the gate's mechanics.
func TestShippedBuildRejectsLuaScripts(t *testing.T) {
	script := filepath.Join(t.TempDir(), "script.lua")
	if err := os.WriteFile(script, []byte("function HandleRoute() end\nfunction HandleDNSQuery() end\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, config string }{
		{"routing", `{"routing": {"script": %q}, "outbounds": [{"protocol": "freedom"}]}`},
		{"dns", `{"dns": {"script": %q, "servers": ["1.1.1.1"]}, "outbounds": [{"protocol": "freedom"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var config Config
			if err := json.Unmarshal([]byte(fmt.Sprintf(tc.config, script)), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if err != nil {
				t.Fatal(err)
			}
			instance, err := core.New(built)
			if err == nil {
				instance.Close()
				t.Fatal("the shipping build accepted a Lua script")
			}
			if !strings.Contains(err.Error(), xlua.ErrScriptsDisabled.Error()) {
				t.Fatalf("core.New error = %v, want %q", err, xlua.ErrScriptsDisabled)
			}
		})
	}
}
