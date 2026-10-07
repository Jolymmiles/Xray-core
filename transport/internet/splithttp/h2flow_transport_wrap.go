//go:build go1.27 && !http2legacy

package splithttp

import (
	"net/http"

	"golang.org/x/net/http2"
)

// unlinkH2Transport leaves t1 as a plain http2.Transport would have created
// it, apart from the HTTP/2 settings: ConfigureTransports also turns on
// HTTP/1 and sets a TLS config, which a transport that dials its own
// connections does not want.
func unlinkH2Transport(t1 *http.Transport, _ *http2.Transport) {
	t1.Protocols = nil
	t1.TLSClientConfig = nil
}
