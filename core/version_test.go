package core_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
)

func TestVersionHasUTCPanelSuffix(t *testing.T) {
	got := core.Version()
	if !strings.HasSuffix(got, ".utc1442") {
		t.Fatalf("Version() = %q, want .utc1442 suffix for panel display", got)
	}
	want := fmt.Sprintf("%d.%d.%d.utc1442", core.Version_x, core.Version_y, core.Version_z)
	if got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
}
