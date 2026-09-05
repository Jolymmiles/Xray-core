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
	structuralGate := filepath.Join(root, "testing", "release", "structural_presence.sh")
	assertFileContains(t, structuralGate, []string{
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
		"XRAY_SMUX_STRESS_TCP_STREAMS=16",
		"TestRemnaNodeLinuxReleaseEnvironment",
		"XRAY_STRUCTURAL_SOAK_SECONDS",
		"mixed-path soak cycle",
		"TestSMUXProcessInteropMatrix|TestH2MUXProcessInteropMatrix)$",
		"TestDirectVersionSkew|TestLegacyMuxVersionSkew|TestXUDPVersionSkew|TestReverseVersionSkew|TestWireGuardVersionSkew)$",
		"XRAY_NATIVE_LINUX_RELEASE must be 1",
		"GOAMD64=v1",
		"go version -m",
	})
	gateSource, err := os.ReadFile(structuralGate)
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(gateSource), "-run '^TestSMUXProcessStressAndReconnect$'"); count != 2 {
		t.Fatalf("release gate stress profiles = %d, want peak and cumulative profiles", count)
	}
	peakCommand := "XRAY_SMUX_STRESS_CYCLES= XRAY_SMUX_STRESS_TCP_STREAMS= go test"
	cumulativeCommand := "XRAY_SMUX_STRESS_CYCLES=50 XRAY_SMUX_STRESS_TCP_STREAMS=16 go test"
	peakIndex := strings.Index(string(gateSource), peakCommand)
	cumulativeIndex := strings.Index(string(gateSource), cumulativeCommand)
	if peakIndex < 0 || cumulativeIndex < 0 || peakIndex >= cumulativeIndex {
		t.Fatalf("release gate must run hermetic peak stress before cumulative stress")
	}
	releaseWorkflow := filepath.Join(root, ".github", "workflows", "release.yml")
	assertFileContains(t, releaseWorkflow, []string{
		"name: Build and Release",
		"workflow_dispatch:",
		"release:",
		"types: [published]",
		"build:",
		"needs: check-assets",
		"Upload binaries to release",
	})
	assertFileNotContains(t, releaseWorkflow, []string{
		"\n  push:\n",
		"\n  pull_request:\n",
		"release-validation:",
		"testing/release/structural_presence.sh linux",
		"needs: [check-assets, release-validation]",
	})
	validationWorkflow := filepath.Join(root, ".github", "workflows", "pre-release-validation.yml")
	assertFileContains(t, validationWorkflow, []string{
		"name: Pre-release Validation",
		"workflow_dispatch:",
		"release-validation:",
		"runs-on: ubuntu-24.04",
		"fetch-depth: 0",
		"XRAY_STRUCTURAL_SOAK_SECONDS: 1800",
		"XRAY_E2E_YT_INTERFACE: yt",
		"XRAY_NATIVE_LINUX_RELEASE: 1",
		"testing/release/structural_presence.sh linux",
		"mvdan.cc/gofumpt@v0.11.0",
		"Restore Geodat Cache for release validation",
		"test -s resources/geoip.dat",
		"test -s resources/geosite.dat",
		"repository: Jolymmiles/sing-box",
		"ref: 46f00de9aa060ab989353953051268c7c4745664",
		"repository: Jolymmiles/mihomo",
		"ref: 2e1394a7cf4c2d25ac6290a05ee0e21f786073de",
		"SING_BOX_E2E_BIN=",
		"MIHOMO_E2E_BIN=",
		"rm -rf .interop",
	})
	assertFileNotContains(t, validationWorkflow, []string{
		"\n  release:\n",
		"\n  push:\n",
		"\n  pull_request:\n",
	})
	assertFileContains(t, filepath.Join(root, "common", "singmux", "candidate_performance_integration_test.go"), []string{
		"b7bdfb03fa582cd691197593cc853f6ea209d04f",
		"v26.8.25-1457",
		"TestCandidatePerformanceAgainstPreviousRelease",
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

func assertFileNotContains(t *testing.T, path string, forbidden []string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range forbidden {
		if strings.Contains(string(content), marker) {
			t.Errorf("%s unexpectedly contains %q", filepath.ToSlash(path), marker)
		}
	}
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
