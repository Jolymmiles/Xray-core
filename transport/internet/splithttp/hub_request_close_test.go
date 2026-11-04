package splithttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
)

// The worker serves a connection inline, so addConn returns only once the
// session is over. A GET that ends while addConn still runs must close the
// connection itself, or a read of the upload queue waits forever.
func TestSplitHTTPGetClosesConnWhenRequestContextEnds(t *testing.T) {
	config := &Config{Path: "/sh", XPaddingBytes: &RangeConfig{From: 1, To: 1}}
	readErr := make(chan error, 1)
	reading := make(chan struct{})
	handler := &requestHandler{
		config:    config,
		path:      config.GetNormalizedPath(),
		sessionMu: new(sync.Mutex),
		ln: &Listener{
			config: config,
			addConn: func(conn stat.Connection) {
				close(reading)
				// Reads as mux.ServerWorker.run does: blocks until a read fails.
				_, err := conn.Read(make([]byte, 2))
				readErr <- err
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "https://example.com/sh/session-1?x_padding=X", nil).WithContext(ctx)

	served := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), request)
		close(served)
	}()

	select {
	case <-reading:
	case <-time.After(2 * time.Second):
		t.Fatal("addConn was not called for the GET request")
	}
	// The client, or a proxy in front of the server, ends the GET.
	cancel()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("Read returned nil error after the GET request ended")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read on the upload queue is still blocked after the GET request ended")
	}
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after the GET request ended")
	}
	if _, ok := handler.sessions.Load("session-1"); ok {
		t.Fatal("session was not removed after the GET request ended")
	}
}
