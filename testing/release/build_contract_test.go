package release

import (
	"path/filepath"
	"runtime"
	"testing"
)

// Every shipped or release-tested binary is built with Go 1.27.2 and
// `-tags http2legacy`. Without the tag, Go 1.27's x/net http2.Transport wraps
// net/http: before x/net v0.60.0 it dialed once per request while a TLS
// handshake hung, defeating XHTTP's xmux.maxConnections, and when a
// connection resets right after its handshake it still redials back to back,
// without the 1 to 32 second backoff of x/net's own pool. Censors can act on
// both connection patterns (XTLS/Xray-core#6797).
func TestReleaseBuildsUseGo1272AndHTTP2Legacy(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	for _, check := range []struct {
		path     string
		required []string
	}{
		{"go.mod", []string{"\ngo 1.27.2\n"}},
		{".github/workflows/release.yml", []string{"go build -tags http2legacy "}},
		{".github/workflows/test.yml", []string{"GOFLAGS: -tags=http2legacy", "check-vet:", "run: go vet ./..."}},
		{".github/workflows/pre-release-validation.yml", []string{"GOFLAGS: -tags=http2legacy"}},
		{".github/docker/Dockerfile", []string{"golang:1.27.2 ", "go build -tags http2legacy "}},
		{".github/docker/Dockerfile.usa", []string{"golang:1.27.2 ", "go build -tags http2legacy "}},
		{"testing/release/structural_presence.sh", []string{"-tags=http2legacy"}},
	} {
		assertFileContains(t, filepath.Join(root, filepath.FromSlash(check.path)), check.required)
	}
}
