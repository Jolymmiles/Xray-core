//go:build !go1.27 || http2legacy

package splithttp

import (
	"net/http"

	"golang.org/x/net/http2"
)

// unlinkH2Transport gives t2 its own dialing connection pool: the one
// ConfigureTransports installs only takes connections net/http dialed.
func unlinkH2Transport(_ *http.Transport, t2 *http2.Transport) {
	t2.ConnPool = nil
}
