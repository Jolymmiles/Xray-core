package splithttp

import (
	"bytes"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// A request whose HEADERS carry END_STREAM has no body. Stock never sends a
// stream WINDOW_UPDATE once the peer has closed its side (noteBodyRead skips
// half-closed (remote) streams), so the governor must not grant upload credit
// to such a request either: every GET would otherwise answer with a frame
// stock never sends.
func TestFlowNoUploadCreditForEndedRequest(t *testing.T) {
	_, addr := startFlowServer(t, testUp, testDown, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte(http2.ClientPreface))
	fr := http2.NewFramer(c, c)
	fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	// Open the stream only once the server's SETTINGS, and with them the
	// window it really grants, have passed the governor.
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := f.(*http2.SettingsFrame); ok && !s.IsAck() {
			fr.WriteSettingsAck()
			break
		}
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "http"}, {":authority", "x"}, {":path", "/"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndStream: true, EndHeaders: true})
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if wu, ok := f.(*http2.WindowUpdateFrame); ok && wu.StreamID == 1 {
			t.Fatalf("server granted %d bytes of upload credit on stream 1, whose request already ended", wu.Increment)
		}
		if f.Header().StreamID == 1 && f.Header().Flags.Has(http2.FlagDataEndStream) {
			return
		}
	}
}

// TestFlowGuardProbesOnlyWaitingStreams fires the guard with no stream
// waiting for credit any more, then with one waiting: only the second may
// send a PING.
func TestFlowGuardProbesOnlyWaitingStreams(t *testing.T) {
	h := newFlowHarness(t)
	h.openStream(4 << 20)
	h.conn.take()
	h.c.mu.Lock()
	h.c.incremental = false
	h.c.mu.Unlock()

	h.c.fireGuard()
	h.sync()
	if got := len(pings(t, h.conn.take())); got != 0 || queuedBytes(h.c) != 0 {
		t.Fatalf("guard sent %d PINGs (%d bytes queued) with no stream waiting", got, queuedBytes(h.c))
	}

	h.c.mu.Lock()
	h.c.streams[1].down.waiting = time.Now()
	h.c.mu.Unlock()
	h.c.fireGuard()
	h.sync()
	if got := len(pings(t, h.conn.take())); got != 1 {
		t.Fatalf("guard sent %d PINGs for a waiting stream, want 1", got)
	}
}
