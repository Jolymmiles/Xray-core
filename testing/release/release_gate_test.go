package release

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStructuralPresenceReleaseGateContract(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	assertFileContains(t, filepath.Join(root, "testing", "release", "structural_presence.sh"), []string{
		"GOFUMPT_VERSION=v0.11.0",
		"go run ./infra/vformat/main.go -mode check -pwd ./",
		"go vet ./...",
		"go test -timeout 2h ./...",
		"go test -race ./...",
		"go test -gcflags=all=-d=checkptr=2 ./...",
		"TestSMUXProcessInteropMatrix|TestH2MUXProcessInteropMatrix",
		"TestDirectVersionSkew|TestLegacyMuxVersionSkew|TestXUDPVersionSkew|TestReverseVersionSkew|TestWireGuardVersionSkew",
		"TestSevenThousandExactOwnersEndAtZero",
		"XRAY_SMUX_STRESS_CYCLES=50",
		"TestSMUXServerPerformanceAgainstSingMux|TestCandidatePerformanceAgainstV26815",
		"TestRemnaNodeLinuxReleaseEnvironment",
		"XRAY_STRUCTURAL_SOAK_SECONDS",
		"mixed-path soak cycle",
		"TestSMUXProcessInteropMatrix|TestH2MUXProcessInteropMatrix)$",
		"TestDirectVersionSkew|TestLegacyMuxVersionSkew|TestXUDPVersionSkew|TestReverseVersionSkew|TestWireGuardVersionSkew)$",
		"XRAY_NATIVE_LINUX_RELEASE must be 1",
		"GOAMD64=v1",
		"go version -m",
	})
	assertFileContains(t, filepath.Join(root, ".github", "workflows", "release.yml"), []string{
		"release-validation:",
		"runs-on: ubuntu-24.04",
		"XRAY_STRUCTURAL_SOAK_SECONDS: 1800",
		"XRAY_E2E_YT_INTERFACE: yt",
		"XRAY_NATIVE_LINUX_RELEASE: 1",
		"testing/release/structural_presence.sh linux",
		"mvdan.cc/gofumpt@v0.11.0",
		"needs: [check-assets, release-validation]",
	})
	assertFileContains(t, filepath.Join(root, "common", "singmux", "TESTING.md"), []string{
		"testing/release/structural_presence.sh linux",
		"non-skippable",
	})
	assertFileContains(t, filepath.Join(root, "common", "singmux", "BASELINE.md"), []string{
		"Structural online presence release gate (2026-08-13)",
		"Linux runtime evidence remains pending",
	})
}

func assertFileContains(t *testing.T, path string, required []string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range required {
		if !strings.Contains(string(content), marker) {
			t.Errorf("%s is missing %q", filepath.ToSlash(path), marker)
		}
	}
}
