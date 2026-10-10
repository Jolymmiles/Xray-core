package main

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		request func() *http.Request
		body    string
	}{
		{"ping", servePing, func() *http.Request { return httptest.NewRequest(http.MethodGet, "/ping", nil) }, "pong"},
		{"up", serveUp, func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/up?rate=100000", strings.NewReader("abc"))
		}, "3"},
		{"hello", serveHello, func() *http.Request { return httptest.NewRequest(http.MethodGet, "/", nil) }, "hello"},
	} {
		logged.Reset()
		rec := httptest.NewRecorder()
		tc.handler(rec, tc.request())
		if rec.Code != http.StatusOK || rec.Body.String() != tc.body || logged.Len() != 0 {
			t.Errorf("%s: got %d %q, log %q; want 200 %q and no log", tc.name, rec.Code, rec.Body.String(), logged.String(), tc.body)
		}

		tc.handler(&goneWriter{}, tc.request())
		if !strings.Contains(logged.String(), "connection reset by peer") {
			t.Errorf("%s: a response it could not write is not logged; log %q", tc.name, logged.String())
		}
	}
}
