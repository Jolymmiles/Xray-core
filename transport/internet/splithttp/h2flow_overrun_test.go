package splithttp

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestFlowUploadPastWindowAsStock sends a stream its whole shown upload
// window and then a frame past it, with and without END_STREAM, to a stock
// server and to a governed one, and has each handler read the body once the
// reset is out: the governed handler gets what the stock one does. The
// governor forwarded the frame before the reset, its stack took it into the
// body, and with END_STREAM the handler read past the window with no error.
func TestFlowUploadPastWindowAsStock(t *testing.T) {
	for _, endStream := range []bool{true, false} {
		t.Run(map[bool]string{true: "end_stream_true", false: "end_stream_false"}[endStream], func(t *testing.T) {
			type result struct {
				n   int
				err error
			}
			run := func(t *testing.T, governed bool) result {
				startRead := make(chan struct{})
				gotCh := make(chan result, 2)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/bump" {
						io.Copy(io.Discard, r.Body)
						return
					}
					<-startRead
					b, err := io.ReadAll(r.Body)
					gotCh <- result{len(b), err}
				})

				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()

				var listener net.Listener = ln
				h2cfg := &http.HTTP2Config{
					MaxReceiveBufferPerStream:     flowShownUp, // 1 MiB on stock
					MaxReceiveBufferPerConnection: flowServerReceiveWindow,
				}
				if governed {
					h2cfg = (&Config{H2Flow: &H2FlowConfig{Mode: 1}}).h2ReceiveConfig(true)
					listener = &flowListener{
						Listener:   ln,
						up:         flowDefault,
						down:       flowDefault,
						connWindow: h2ConnWindow(h2cfg),
					}
				}
				protocols := new(http.Protocols)
				protocols.SetUnencryptedHTTP2(true)
				srv := &http.Server{
					Handler:   handler,
					Protocols: protocols,
					HTTP2:     h2cfg,
				}
				go srv.Serve(listener)
				defer srv.Close()

				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write([]byte(h2Preface)); err != nil {
					t.Fatal(err)
				}
				fr := http2.NewFramer(conn, conn)
				if err := fr.WriteSettings(); err != nil {
					t.Fatal(err)
				}

				for {
					f, err := fr.ReadFrame()
					if err != nil {
						t.Fatal(err)
					}
					if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
						fr.WriteSettingsAck()
						break
					}
				}

				var hb1, hb3 bytes.Buffer
				enc1 := hpack.NewEncoder(&hb1)
				for _, kv := range [][2]string{
					{":method", "POST"},
					{":scheme", "http"},
					{":path", "/upload"},
					{":authority", "example.com"},
				} {
					enc1.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
				}
				enc3 := hpack.NewEncoder(&hb3)
				for _, kv := range [][2]string{
					{":method", "POST"},
					{":scheme", "http"},
					{":path", "/bump"},
					{":authority", "example.com"},
				} {
					enc3.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
				}

				// Open stream 1 (handler waits on startRead) and stream 3 (handler
				// drains 64 KiB without closing stream 3 so connection window grows
				// by 256 KiB while stream 1's window stays 1 MiB).
				if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb1.Bytes(), EndHeaders: true}); err != nil {
					t.Fatal(err)
				}
				if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: hb3.Bytes(), EndHeaders: true}); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 4; i++ {
					if err := fr.WriteData(3, false, make([]byte, 16384)); err != nil {
						t.Fatal(err)
					}
				}

				// Wait for the connection window to hold all the test sends
				// on stream 1, the frame past its window too, so that only
				// the stream's window is sent past.
				connWin := int64(h2InitWindow) - 4*16384
				for connWin < int64(flowShownUp)+8192 {
					f, err := fr.ReadFrame()
					if err != nil {
						t.Fatal(err)
					}
					if wu, ok := f.(*http2.WindowUpdateFrame); ok && wu.StreamID == 0 {
						connWin += int64(wu.Increment)
					}
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))

				// Send 1 MiB on stream 1 (its entire shown window), then an
				// offending 8 KiB DATA frame past stream 1's 1 MiB window.
				chunk := make([]byte, 16384)
				for sent := 0; sent < flowShownUp; sent += len(chunk) {
					if err := fr.WriteData(1, false, chunk); err != nil {
						t.Fatal(err)
					}
				}
				if err := fr.WriteData(1, endStream, make([]byte, 8192)); err != nil {
					t.Fatal(err)
				}

				// Wait for the server's RST_STREAM(1, FLOW_CONTROL_ERROR) on the wire,
				// proving the server already processed the offending DATA frame, then
				// let the handler read r.Body.
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						t.Fatal(err)
					}
					if rst, ok := f.(*http2.RSTStreamFrame); ok && rst.StreamID == 1 {
						break
					}
				}
				close(startRead)
				return <-gotCh
			}

			stockRes := run(t, false)
			govRes := run(t, true)
			t.Logf("endStream=%v -> stock handler: n=%d err=%v; governed handler: n=%d err=%v",
				endStream, stockRes.n, stockRes.err, govRes.n, govRes.err)
			if govRes.n != stockRes.n || (govRes.err == nil) != (stockRes.err == nil) {
				t.Fatalf("endStream=%v: governed handler got (n=%d, err=%v), want stock behavior (n=%d, err=%v)",
					endStream, govRes.n, govRes.err, stockRes.n, stockRes.err)
			}
		})
	}
}
