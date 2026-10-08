package release

import (
	"path/filepath"
	"runtime"
	"testing"
)

// Every shipped or release-tested binary is built with Go 1.27.1 and
// `-tags http2legacy`. Without the tag, Go 1.27's x/net http2.Transport dials
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
		{".github/workflows/test.yml", []string{"GOFLAGS: -tags=http2legacy", "check-vet:", "run: go vet ./..."}},
		{".github/workflows/pre-release-validation.yml", []string{"GOFLAGS: -tags=http2legacy"}},
		{".github/docker/Dockerfile", []string{"golang:1.27.1 ", "go build -tags http2legacy "}},
		{".github/docker/Dockerfile.usa", []string{"golang:1.27.1 ", "go build -tags http2legacy "}},
		{"testing/release/structural_presence.sh", []string{"-tags=http2legacy"}},
	} {
		assertFileContains(t, filepath.Join(root, filepath.FromSlash(check.path)), check.required)
	}
}
