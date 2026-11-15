package connectip

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apernet/quic-go/http3"
)

// failingHTTPStreamer is an HTTP/3 response writer whose response header
// cannot be sent, as quic-go reports it from HTTPStream since v0.65.
type failingHTTPStreamer struct {
	*httptest.ResponseRecorder
	err error
}

func (w failingHTTPStreamer) HTTPStream() (*http3.Stream, error) { return nil, w.err }

func TestProxyReturnsHTTPStreamError(t *testing.T) {
	headerErr := errors.New("sending the response header failed")
	w := failingHTTPStreamer{ResponseRecorder: httptest.NewRecorder(), err: headerErr}

	conn, err := (&Proxy{}).Proxy(w, &ProxyRequest{})
	if !errors.Is(err, headerErr) {
		t.Fatalf("Proxy error = %v, want %v", err, headerErr)
	}
	if conn != nil {
		conn.Close()
		t.Fatal("Proxy returned a connection for a stream it could not take over")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want %d", w.Code, http.StatusOK)
	}
}
