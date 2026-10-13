package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
)

// goneWriter is a response to a client that went away: no write gets through.
type goneWriter struct{ header http.Header }

func (w *goneWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *goneWriter) WriteHeader(int) {}

func (w *goneWriter) Write([]byte) (int, error) {
	return 0, errors.New("connection reset by peer")
}

func TestHandlersLogResponsesTheyCannotWrite(t *testing.T) {
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(prev) })

	request := func(method, target string, body func() io.Reader) func() *http.Request {
		return func() *http.Request { return httptest.NewRequest(method, target, body()) }
	}
	none := func() io.Reader { return nil }
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		request func() *http.Request
		code    int
		body    string
	}{
		{"ping", servePing, request(http.MethodGet, "/ping", none), http.StatusOK, "pong"},
		{"up", serveUp, request(http.MethodPost, "/up?rate=100000", func() io.Reader {
			return strings.NewReader("abc")
		}), http.StatusOK, "3"},
		{"up read as it comes", serveUp, request(http.MethodPost, "/up?rate=0", func() io.Reader {
			return strings.NewReader("abc")
		}), http.StatusOK, "3"},
		{"up with a bad rate", serveUp, request(http.MethodPost, "/up?rate=-1", func() io.Reader {
			return strings.NewReader("abc")
		}), http.StatusBadRequest, "rate must be 0 to 1048576 bytes per second\n"},
		{"down", serveDown, request(http.MethodGet, "/down?bytes=5", none), http.StatusOK, "\x00\x00\x00\x00\x00"},
		{"down without a size", serveDown, request(http.MethodGet, "/down", none), http.StatusBadRequest, "bytes must be a positive number\n"},
		{"up with a broken body", serveUp, request(http.MethodPost, "/up?rate=100000", func() io.Reader {
			return iotest.ErrReader(errors.New("stream reset"))
		}), http.StatusBadRequest, "after 0 bytes: stream reset\n"},
		{"hello", serveHello, request(http.MethodGet, "/", none), http.StatusOK, "hello"},
	} {
		logged.Reset()
		rec := httptest.NewRecorder()
		tc.handler(rec, tc.request())
		if rec.Code != tc.code || rec.Body.String() != tc.body || logged.Len() != 0 {
			t.Errorf("%s: got %d %q, log %q; want %d %q and no log",
				tc.name, rec.Code, rec.Body.String(), logged.String(), tc.code, tc.body)
		}

		tc.handler(&goneWriter{}, tc.request())
		if !strings.Contains(logged.String(), "connection reset by peer") {
			t.Errorf("%s: a response it could not write is not logged; log %q", tc.name, logged.String())
		}
	}
}
