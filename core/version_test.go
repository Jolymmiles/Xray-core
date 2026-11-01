package core_test

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/core"
)

func TestVersionFollowsYearMonthDayHHMM(t *testing.T) {
	got := core.Version()
	want := fmt.Sprintf("%d.%d.%d-1424", core.Version_x, core.Version_y, core.Version_z)
	if got != want {
		t.Fatalf("Version() = %q, want %q (year.month.day-HHMM UTC)", got, want)
	}
	if core.Version_x != 26 || core.Version_y != 11 || core.Version_z != 1 {
		t.Fatalf("numeric version = %d.%d.%d, want 26.11.1", core.Version_x, core.Version_y, core.Version_z)
	}
}
