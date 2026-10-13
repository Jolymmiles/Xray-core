//go:build !go1.27 || http2legacy

package splithttp

// x/net's own HTTP/2 client, which release builds keep, advertises the
// RFC 9113 default frame size.
const wantClientMaxFrameSize = 16 << 10
