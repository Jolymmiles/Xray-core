package release

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestStructuralPresenceGoTestsSetTimeouts reads every go test command of the
// release gate. Each must set -timeout: without it go test kills a package
// after 10 minutes, and transport/internet/splithttp outlasted that under
// checkptr in Pre-release Validation run 38402808282 while its tests still
// progressed.
func TestStructuralPresenceGoTestsSetTimeouts(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	gate, err := os.ReadFile(filepath.Join(root, "testing", "release", "structural_presence.sh"))
	if err != nil {
		t.Fatal(err)
	}
	goTest := regexp.MustCompile(`(^|\s)go test\s`)
	timeout := regexp.MustCompile(`\s-timeout[= ]\S`)
	commands := 0
	for _, command := range strings.Split(strings.ReplaceAll(string(gate), "\\\n", " "), "\n") {
		if !goTest.MatchString(command) {
			continue
		}
		commands++
		if !timeout.MatchString(command) {
			t.Errorf("the release gate runs %q without -timeout", strings.Join(strings.Fields(command), " "))
		}
	}
	if commands == 0 {
		t.Fatal("the release gate has no go test command")
	}
}
