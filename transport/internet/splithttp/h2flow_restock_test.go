package splithttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFlowChainedPausedReaderKeepsConnection has a governed client behind a
// governed server, as ListenXH and the dialer set them up, and a reader that
// waits until the server can send no more before it reads the body. Credit
// the client forwarded before it saw the server's tag went against the
// protocol default; a restock that raised the shown window to the stack's
// own added the raise on top of it, the server sent past the stack's window,
// and the stack closed the connection with FLOW_CONTROL_ERROR. A stock client
// is the control.
func TestFlowChainedPausedReaderKeepsConnection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		window   int
		governed bool
	}{
		{"governed 96 KiB", 96 << 10, true},
		{"governed 512 KiB", 512 << 10, true},
		{"governed 2 MiB", 2 << 20, true},
		{"governed default", 0, true},
		{"stock 256 KiB", 256 << 10, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var written atomic.Int64
			tl, addr := startFlowServer(t, testUp, testDown, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				buf := make([]byte, 16<<10)
				for range 640 {
					n, err := w.Write(buf)
					written.Add(int64(n))
					if err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			tl.mu.Lock()
			tl.sendWindow = flowServerSendWindow
			tl.mu.Unlock()
			var conf *http.HTTP2Config
			if tc.window != 0 {
				conf = &http.HTTP2Config{MaxReceiveBufferPerStream: tc.window}
			}
			tr := newH2Transport(conf)
			tr.AllowHTTP = true
			var mu sync.Mutex
			var gc *flowConn
			tr.DialTLSContext = func(ctx context.Context, network, _ string, _ *gotls.Config) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil || !tc.governed {
					return c, err
				}
				g := newFlowClientConn(c)
				mu.Lock()
				gc = g
				mu.Unlock()
				return g, nil
			}
			t.Cleanup(func() {
				tr.CloseIdleConnections()
				mu.Lock()
				defer mu.Unlock()
				if gc != nil {
					gc.Close()
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://x/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := (&http.Client{Transport: tr}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			// The reader waits until the server's writes stop: its window
			// at the server is used up.
			last, still := int64(-1), 0
			for still < 10 {
				time.Sleep(20 * time.Millisecond)
				if n := written.Load(); n == last {
					still++
				} else {
					last, still = n, 0
				}
			}
			if tc.governed {
				mu.Lock()
				g := gc
				mu.Unlock()
				g.mu.Lock()
				peer := g.peerGoverned
				g.mu.Unlock()
				if !peer {
					t.Fatal("the client did not see the server govern: no restock to test")
				}
			}
			if n, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatalf("server wrote %d before the reader read; read %d of the body: %v", last, n, err)
			}
		})
	}
}
