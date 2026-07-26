package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/reality"
)

// buildREALITYServer builds a minimal valid REALITY server config with the
// caller's extra fields merged in.
func buildREALITYServer(t *testing.T, extra string) (*reality.Config, error) {
	t.Helper()

	raw := `{
		"show": false,
		"dest": "example.com:443",
		"serverNames": ["example.com"],
		"privateKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"shortIds": [""]` + extra + `
	}`

	config := new(conf.REALITYConfig)
	if err := json.Unmarshal([]byte(raw), config); err != nil {
		t.Fatalf("failed to unmarshal REALITY config: %v", err)
	}
	message, err := config.Build()
	if err != nil {
		return nil, err
	}
	built, ok := message.(*reality.Config)
	if !ok {
		t.Fatalf("Build returned %T, want *reality.Config", message)
	}
	return built, nil
}

func TestREALITYClientVerParsing(t *testing.T) {
	tests := []struct {
		name    string
		extra   string
		wantMin []byte
		wantMax []byte
		wantErr bool
	}{
		{
			name:    "unset leaves both bounds disabled",
			extra:   "",
			wantMin: nil,
			wantMax: nil,
		},
		{
			name:    "minClientVer is parsed",
			extra:   `, "minClientVer": "26.3.27"`,
			wantMin: []byte{26, 3, 27},
			wantMax: nil,
		},
		{
			name:    "maxClientVer is parsed",
			extra:   `, "maxClientVer": "1.2.3"`,
			wantMin: nil,
			wantMax: []byte{1, 2, 3},
		},
		{
			name:    "both bounds are parsed",
			extra:   `, "minClientVer": "1.2.3", "maxClientVer": "255.255.255"`,
			wantMin: []byte{1, 2, 3},
			wantMax: []byte{255, 255, 255},
		},
		{
			name:    "short version pads missing components with zero",
			extra:   `, "minClientVer": "26"`,
			wantMin: []byte{26, 0, 0},
			wantMax: nil,
		},
		{
			name:    "component above 255 is rejected",
			extra:   `, "minClientVer": "26.3.256"`,
			wantErr: true,
		},
		{
			name:    "non numeric component is rejected",
			extra:   `, "minClientVer": "26.x.27"`,
			wantErr: true,
		},
		{
			name:    "more than three components is rejected",
			extra:   `, "maxClientVer": "1.2.3.4"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			built, err := buildREALITYServer(t, tt.extra)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := built.MinClientVer; !bytesEqual(got, tt.wantMin) {
				t.Errorf("MinClientVer = %v, want %v", got, tt.wantMin)
			}
			if got := built.MaxClientVer; !bytesEqual(got, tt.wantMax) {
				t.Errorf("MaxClientVer = %v, want %v", got, tt.wantMax)
			}
		})
	}
}

// TestREALITYClientVerHasNoBuiltInDefault pins the fork behavior: upstream
// forces minClientVer to 26.3.27 when the operator leaves it unset, this fork
// must leave the gate disabled unless it is configured explicitly.
func TestREALITYClientVerHasNoBuiltInDefault(t *testing.T) {
	built, err := buildREALITYServer(t, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if built.MinClientVer != nil {
		t.Errorf("MinClientVer = %v, want nil (no hardcoded default)", built.MinClientVer)
	}
	if built.MaxClientVer != nil {
		t.Errorf("MaxClientVer = %v, want nil (no hardcoded default)", built.MaxClientVer)
	}
}

func bytesEqual(got, want []byte) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
