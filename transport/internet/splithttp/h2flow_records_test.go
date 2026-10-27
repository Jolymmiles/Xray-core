package splithttp

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/http2"
)

// writeSizes records the size of each write to the connection under it: what
// a TLS layer above the TCP connection would send as one record each.
type writeSizes struct {
	net.Conn
	mu    sync.Mutex
	sizes []int
}

func (w *writeSizes) Write(b []byte) (int, error) {
	w.mu.Lock()
	w.sizes = append(w.sizes, len(b))
	w.mu.Unlock()
	return w.Conn.Write(b)
}

// TestFlowClientRecordSizes logs the writes a client makes toward the server
// at the start of a download, the TLS records an observer of the path would
// see, for a stock client, a governed client toward a stock server and a
// governed client toward a governed server, which sees the server govern and
// sends its own SETTINGS. That SETTINGS goes in a write the client makes in
// any case: toward a governed server it makes no more writes than a stock
// client does.
func TestFlowClientRecordSizes(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 256<<10))
	})
	sizes := map[string][]int{}
	for _, tc := range []struct {
		name             string
		server, governed bool
	}{
		{"stock client, stock server", false, false},
		{"stock client, governed server", true, false},
		{"governed client, stock server", false, true},
		{"governed client, governed server", true, true},
	} {
		up, down := flowLimit{}, flowLimit{}
		if tc.server {
			up, down = testUp, testDown
		}
		_, addr := startFlowServer(t, up, down, false, handler)
		rec := &writeSizes{}
		var fc *flowConn
		tr := &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, _ string, _ *gotls.Config) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				rec.Conn = c
				if tc.governed {
					g := newFlowClientConn(rec)
					rec.mu.Lock()
					fc = g
					rec.mu.Unlock()
					return g, nil
				}
				return rec, nil
			},
		}
		// A governed connection holds its flowGroup until it closes: close
		// it with the test, whichever way the test ends.
		t.Cleanup(func() {
			tr.CloseIdleConnections()
			rec.mu.Lock()
			g := fc
			rec.mu.Unlock()
			if g != nil {
				g.Close()
			}
		})
		client := &http.Client{Transport: tr}
		resp, err := client.Get("http://x/")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		client.CloseIdleConnections()
		rec.mu.Lock()
		got := append([]int(nil), rec.sizes...)
		rec.mu.Unlock()
		sizes[tc.name] = got
		var b strings.Builder
		for i, n := range got {
			if i == 16 {
				fmt.Fprintf(&b, " ... (%d writes)", len(got))
				break
			}
			fmt.Fprintf(&b, " %d", n)
		}
		t.Logf("%s:%s", tc.name, b.String())
	}
	// Toward a governed server, the governed client differs from a stock one
	// by its SETTINGS alone, 15 bytes in a write both make.
	stock, governed := sizes["stock client, governed server"], sizes["governed client, governed server"]
	if len(governed) > len(stock) {
		t.Errorf("toward a governed server a governed client made %d writes, a stock one %d", len(governed), len(stock))
	}
}
