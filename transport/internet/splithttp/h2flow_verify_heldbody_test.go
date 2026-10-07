package splithttp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// startWiredFlowServer serves h the way ListenXH serves a TCP listener, with
// the governor on or off through "h2Flow".
func startWiredFlowServer(t *testing.T, governed bool, h http.Handler) string {
	t.Helper()
	mode := int32(2)
	if governed {
		mode = 1
	}
	config := &Config{H2Flow: &H2FlowConfig{Mode: mode}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var listener net.Listener = ln
	if config.h2FlowOn() {
		listener = &flowListener{Listener: ln, up: flowDefault, down: flowDefault}
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: h, Protocols: protocols, HTTP2: config.h2ReceiveConfig(true)}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// A packet-up POST handler reads its whole body and then waits in
// uploadQueue.Push while its session's reader is slow; it answers only once
// the queue has room. A body that fits one DATA frame arrives with
// END_STREAM, so the server never returns stream credit for it, only
// connection credit, as soon as the handler reads it. Stock thus lets the
// client go on uploading on that connection, for this session and every
// other one. The governor must not count such a body as unread until the
// response ends, nor need a new frame from the server to hand back the
// connection credit once it does.
func TestFlowReadBodiesReleaseConnectionWindow(t *testing.T) {
	const posts, size = 64, 16 << 10 // 1 MiB: the connection window shown
	for _, governed := range []bool{false, true} {
		t.Run(fmt.Sprintf("governed=%v", governed), func(t *testing.T) {
			read := make(chan struct{}, posts)
			unblock := make(chan struct{})
			var unblockOnce sync.Once
			release := func() { unblockOnce.Do(func() { close(unblock) }) }
			t.Cleanup(release)
			addr := startWiredFlowServer(t, governed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.ReadFull(r.Body, make([]byte, size))
				read <- struct{}{}
				select {
				case <-unblock:
				case <-r.Context().Done():
				}
			}))

			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(20 * time.Second))
			c.Write([]byte(http2.ClientPreface))
			fr := http2.NewFramer(c, c)
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})

			var mu sync.Mutex
			window := int64(65535) // connection credit the client holds
			answered := 0
			settled := make(chan struct{})
			go func() {
				var once sync.Once
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					mu.Lock()
					switch f := f.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							fr.WriteSettingsAck()
						}
					case *http2.WindowUpdateFrame:
						if f.StreamID == 0 {
							window += int64(f.Increment)
							once.Do(func() { close(settled) })
						}
					case *http2.HeadersFrame:
						if f.StreamEnded() {
							answered++
						}
					case *http2.DataFrame:
						if f.StreamEnded() {
							answered++
						}
					}
					mu.Unlock()
				}
			}()
			select {
			case <-settled:
			case <-time.After(5 * time.Second):
				t.Fatal("no connection window from the server")
			}
			credit := func() int64 {
				mu.Lock()
				defer mu.Unlock()
				return window
			}

			var block bytes.Buffer
			enc := hpack.NewEncoder(&block)
			for i := 0; i < posts; i++ {
				if credit() < size {
					t.Fatalf("request %d: %d bytes of connection credit, %d needed", i, credit(), size)
				}
				block.Reset()
				for _, hf := range [][2]string{{":method", "POST"}, {":scheme", "http"}, {":authority", "x"}, {":path", "/held"}, {"content-length", strconv.Itoa(size)}} {
					enc.WriteField(hpack.HeaderField{Name: hf[0], Value: hf[1]})
				}
				id := uint32(2*i + 1)
				mu.Lock()
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true})
				fr.WriteData(id, true, make([]byte, size))
				window -= size
				mu.Unlock()
			}
			for i := 0; i < posts; i++ {
				select {
				case <-read:
				case <-time.After(5 * time.Second):
					t.Fatalf("only %d of %d bodies reached their handlers", i, posts)
				}
			}

			// Every body is read; stock has handed its connection credit back.
			wait := func() int64 {
				deadline := time.Now().Add(time.Second)
				for credit() < size && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				return credit()
			}
			whileHeld := wait()
			if whileHeld >= size {
				return
			}
			release()
			deadline := time.Now().Add(5 * time.Second)
			for {
				mu.Lock()
				n := answered
				mu.Unlock()
				if n == posts {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%d of %d requests answered after their handlers were released", n, posts)
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("handlers read all %d bytes, yet the client holds %d bytes of connection credit while they wait, and %d once all %d requests are answered: no request on this connection can upload again",
				posts*size, whileHeld, wait(), posts)
		})
	}
}
