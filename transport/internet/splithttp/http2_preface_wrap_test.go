//go:build go1.27 && !http2legacy

package splithttp

// Without http2legacy x/net wraps net/http, whose HTTP/2 client advertises a
// 1 MiB frame size. Release builds do not ship this mode (docs/FORK.md).
const wantClientMaxFrameSize = 1 << 20
