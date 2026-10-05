package release

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every shipped or release-tested binary is built with Go 1.27.1 and
// -tags http2legacy. Without the tag, Go 1.27's x/net http2.Transport dials
// once per request while a TLS handshake hangs, which defeats XHTTP's
// xmux.maxConnections and produces the connection bursts censors block on
// (XTLS/Xray-core#6797).
func TestReleaseBuildsUseGo1271AndHTTP2Legacy(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	for _, check := range []struct {
		path     string
		required []string
	}{
		{"go.mod", []string{"\ngo 1.27.1\n"}},
		{".github/workflows/release.yml", []string{"go build -tags http2legacy "}},
		{".github/workflows/test.yml", []string{"GOFLAGS: -tags=http2legacy"}},
		{".github/workflows/pre-release-validation.yml", []string{"GOFLAGS: -tags=http2legacy"}},
		{".github/docker/Dockerfile", []string{"golang:1.27.1 ", "go build -tags http2legacy "}},
		{".github/docker/Dockerfile.usa", []string{"golang:1.27.1 ", "go build -tags http2legacy "}},
		{"testing/release/structural_presence.sh", []string{"-tags=http2legacy"}},
	} {
		assertFileContains(t, filepath.Join(root, filepath.FromSlash(check.path)), check.required)
	}
}

// An explicit -tags flag replaces the tags in GOFLAGS instead of adding to
// them, so every Xray build or test command that names its own tags must
// list http2legacy too. Interop peers such as sing-box are built as their
// users build them and are not covered here.
func TestExplicitBuildTagsKeepHTTP2Legacy(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	for _, path := range []string{
		"testing/release/structural_presence.sh",
		"testing/scenarios/common_coverage.go",
		"testing/coverage/coverall",
		"common/singmux/TESTING.md",
	} {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, "-tags") && !strings.Contains(line, "http2legacy") {
				t.Errorf("%s:%d sets tags without http2legacy: %s", path, number+1, strings.TrimSpace(line))
			}
		}
	}
}
