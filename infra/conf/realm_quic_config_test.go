package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask/realm"
	"google.golang.org/protobuf/proto"
)

func TestStreamConfigQuicParamsPlumbing(t *testing.T) {
	var config StreamConfig
	if err := json.Unmarshal([]byte(`{"finalmask":{"quicParams":{"brutalDisableLossCompensation":true,"disableChromeParrot":true,"disableGSO":true}}}`), &config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	got := built.QuicParams
	if got == nil || !got.BrutalDisableLossCompensation || !got.DisableChromeParrot || !got.DisableGSO {
		t.Fatalf("new QUIC flags not propagated: %#v", got)
	}

	var omitted StreamConfig
	if err := json.Unmarshal([]byte(`{"finalmask":{"quicParams":{}}}`), &omitted); err != nil {
		t.Fatal(err)
	}
	defaults, err := omitted.Build()
	if err != nil {
		t.Fatal(err)
	}
	if defaults.QuicParams == nil || defaults.QuicParams.BrutalDisableLossCompensation || defaults.QuicParams.DisableChromeParrot || defaults.QuicParams.DisableGSO {
		t.Fatalf("unexpected omitted defaults: %#v", defaults.QuicParams)
	}
}

func TestRealmConfigIPModeAndPortMapping(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		family  realm.Family
		mapping *realm.PortMapping
		wantErr bool
	}{
		{name: "default dual", json: `{}`, family: realm.Family_Dual},
		{name: "v4", json: `{"ipMode":"V4"}`, family: realm.Family_V4},
		{name: "v6 mapping", json: `{"ipMode":"v6","portMapping":{"enabled":true,"timeout":2,"lifetime":30}}`, family: realm.Family_V6, mapping: &realm.PortMapping{Enabled: true, Timeout: 2, Lifetime: 30}},
		{name: "invalid mode", json: `{"ipMode":"bogus"}`, wantErr: true},
		{name: "negative mapping timeout", json: `{"portMapping":{"enabled":true,"timeout":-1}}`, wantErr: true},
		{name: "uint32 mapping lifetime overflow", json: `{"portMapping":{"enabled":true,"lifetime":4294967296}}`, wantErr: true},
		{name: "duration mapping lifetime overflow", json: `{"portMapping":{"enabled":true,"lifetime":9223372037}}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := `{"url":"realm+http://token@example.com/id","stunServers":["stun.example.com:3478"]}`
			var extra map[string]any
			if err := json.Unmarshal([]byte(tt.json), &extra); err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal([]byte(base), &raw); err != nil {
				t.Fatal(err)
			}
			for key, value := range extra {
				raw[key] = value
			}
			encoded, _ := json.Marshal(raw)
			var config Realm
			if err := json.Unmarshal(encoded, &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := built.(*realm.Config)
			if got.IpMode != tt.family {
				t.Fatalf("IP mode = %v, want %v", got.IpMode, tt.family)
			}
			if !proto.Equal(got.PortMapping, tt.mapping) {
				t.Fatalf("mapping = %v, want %v", got.PortMapping, tt.mapping)
			}
		})
	}
}
