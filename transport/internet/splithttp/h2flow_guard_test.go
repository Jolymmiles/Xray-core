package splithttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestFlowGuardNotPutOffByNewStreams has a stream run out of window with a
// client that credits in large steps, and then another one every 40 ms,
// sooner than the guard's delay: the guard still fires for the first.
// Moved for each new stream, it fired only once they stopped coming.
func TestFlowGuardNotPutOffByNewStreams(t *testing.T) {
	defer func(d time.Duration) { flowGuardMin = d }(flowGuardMin)
	flowGuardMin = 100 * time.Millisecond
	c := newFlowConn(&scriptConn{}, flowDefault, flowDefault)
	t.Cleanup(func() { c.Close() })
	c.mu.Lock()
	c.clientInit, c.clientShown = 1<<20, h2InitWindow
	c.incremental = false
	c.rtt = 20 * time.Millisecond
	c.mu.Unlock()
	stuck := func(id uint32) {
		c.mu.Lock()
		defer c.mu.Unlock()
		s := &flowStream{downSent: h2InitWindow}
		c.streams[id] = s
		c.armGuard(s)
	}
	stuck(1)
	for id := uint32(3); id < 23; id += 2 {
		time.Sleep(40 * time.Millisecond)
		c.mu.Lock()
		fired := c.guardProbe
		c.mu.Unlock()
		if fired {
			return
		}
		stuck(id)
	}
	t.Fatalf("stream 1 has waited %v with no probe, the guard's delay being %v", 400*time.Millisecond, flowGuardMin)
}

// TestFlowClientSeesGovernedServer feeds a governed client the server's first
// frames: a PING ahead of any reply marks the server as one that governs its
// downloads, a PING after a reply, as a stock server's keepalive, does not.
func TestFlowClientSeesGovernedServer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		frames   func(fr *http2.Framer)
		governed bool
	}{
		{"tagged PING with the first SETTINGS", func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
			fr.WritePing(false, [8]byte{0x6b, 0x7a, 0x3f, 0x91, 1, 2, 3, 4})
		}, true},
		// A stock server's health check, as http2.Server with ReadIdleTimeout
		// sends while a handler holds its first reply.
		{"untagged early PING", func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
			fr.WritePing(false, [8]byte{1})
		}, false},
		{"PING after a reply", func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x88}, EndHeaders: true})
			fr.WritePing(false, [8]byte{0x6b, 0x7a, 0x3f, 0x91, 1, 2, 3, 4})
		}, false},
		{"no PING", func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFlowClientConn(&scriptConn{})
			t.Cleanup(func() { c.Close() })
			c.mode.Store(flowH2)
			c.fromServer(frames(tc.frames), nil)
			c.mu.Lock()
			got := c.peerGoverned
			c.mu.Unlock()
			if got != tc.governed {
				t.Fatalf("server taken as governed: %v, want %v", got, tc.governed)
			}
		})
	}
}

// TestFlowClientNotFooledByStockHealthCheck puts a governed client in front of
// an unmodified x/net HTTP/2 server with a 10 ms ReadIdleTimeout whose handler
// holds its first reply: the server's health-check PINGs come before any
// reply, and the client must keep governing.
func TestFlowClientNotFooledByStockHealthCheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var fc *flowConn
	var served []net.Conn
	var mu sync.Mutex
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *gotls.Config) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
			if err != nil {
				return nil, err
			}
			g := newFlowClientConn(c)
			mu.Lock()
			fc = g
			mu.Unlock()
			return g, nil
		},
	}
	// The client connection holds a flowGroup until it closes: close it,
	// whatever the test ends with, so that no group outlives the test.
	t.Cleanup(func() {
		ln.Close()
		tr.CloseIdleConnections()
		mu.Lock()
		defer mu.Unlock()
		if fc != nil {
			fc.Close()
		}
		for _, c := range served {
			c.Close()
		}
	})
	srv := &http2.Server{ReadIdleTimeout: 10 * time.Millisecond, PingTimeout: time.Second}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			served = append(served, c)
			mu.Unlock()
			go srv.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(300 * time.Millisecond)
				w.Write([]byte("ok"))
			})})
		}
	}()
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
	io.ReadAll(resp.Body)
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.peerGoverned {
		t.Fatal("a stock server's health-check PING was taken for a governed server")
	}
}

// TestFlowClientMalformedOwnedAckReachesStack drives a governed client through
// its SETTINGS, a governed server's tagged PING and the write that carries
// the client's own SETTINGS, forwards the ACK of the stack's SETTINGS, and
// then has the server send a SETTINGS ACK with a payload, a FRAME_SIZE_ERROR:
// it reaches the stack whole, for the stack to raise, and does not stand for
// the ACK of the governor's SETTINGS.
func TestFlowClientMalformedOwnedAckReachesStack(t *testing.T) {
	sc := &scriptConn{}
	c := newFlowClientConn(sc)
	t.Cleanup(func() { c.Close() })
	c.mode.Store(flowH2)
	if _, err := c.writeToServer(frames(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	})); err != nil {
		t.Fatal(err)
	}
	c.fromServer(frames(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		fr.WritePing(false, [8]byte{0x6b, 0x7a, 0x3f, 0x91, 1, 2, 3, 4})
	}), nil)
	if _, err := c.writeToServer(frames(func(fr *http2.Framer) {
		fr.WritePing(true, [8]byte{0x6b, 0x7a, 0x3f, 0x91, 1, 2, 3, 4})
	})); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	owned := len(c.settingsOwn) == 2 && c.settingsOwn[1]
	c.mu.Unlock()
	if !owned {
		t.Fatal("the client sent no SETTINGS of its own")
	}
	if out := c.fromServer(frames(func(fr *http2.Framer) { fr.WriteSettingsAck() }), nil); len(out) != h2FrameHeader {
		t.Fatalf("the ACK of the stack's SETTINGS reached it as %d bytes", len(out))
	}
	bad := []byte{0, 0, 6, h2Settings, h2FlagAck, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1}
	if out := c.fromServer(append([]byte(nil), bad...), nil); len(out) != len(bad) {
		t.Fatalf("a SETTINGS ACK with a payload reached the stack as %d of its %d bytes", len(out), len(bad))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.settingsOwn) != 1 || !c.settingsOwn[0] {
		t.Fatalf("the malformed ACK took the governor's SETTINGS off the queue: %v", c.settingsOwn)
	}
}
