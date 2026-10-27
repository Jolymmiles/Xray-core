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

// TestFlowDroppedOverrunTakesNoConnWindow has a stream that read part of its
// body send a frame past its shown upload window: the dropped frame takes
// nothing from the connection window, and nothing but the reset goes to the
// client, as with a stack that refuses it. The governor counted the frame
// returned and gave back what its release allowed, which for a stream that
// had read was nothing, and a sibling's legal upload then closed the
// connection; where it did give credit back, a stock server sends none.
func TestFlowDroppedOverrunTakesNoConnWindow(t *testing.T) {
	h := newFlowHarness(t)
	t.Cleanup(func() { h.c.Close() })
	h.track()
	h.openStream(4 << 20)
	h.toClient.open(1)

	h.fromServer(func(fr *http2.Framer) {
		fr.WriteWindowUpdate(0, 8<<20)
	})
	// The handler reads the first 64 KiB and returns both credits.
	h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, 1, 64<<10) })
	h.fromServer(func(fr *http2.Framer) {
		fr.WriteWindowUpdate(0, 64<<10)
		fr.WriteWindowUpdate(1, 64<<10)
	})
	h.fromClient(func(fr *http2.Framer) { writeDataSplit(fr, 1, flowShownUp-(64<<10)) })
	h.conn.take()

	h.c.mu.Lock()
	before := h2InitWindow + h.c.upConnForwarded - h.c.upConnSent
	h.c.mu.Unlock()
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteData(1, false, make([]byte, 16384))
	})
	h.sync()
	toClient := h.conn.take()

	h.c.mu.Lock()
	after := h2InitWindow + h.c.upConnForwarded - h.c.upConnSent
	h.c.mu.Unlock()
	if after != before {
		t.Fatalf("the dropped frame took %d bytes of the connection window (%d before, %d after)", before-after, before, after)
	}
	for _, f := range rawFrames(t, toClient) {
		if f.typ != h2RSTStream {
			t.Fatalf("frame of type %d went to the client with the reset; a stock server sends only RST_STREAM", f.typ)
		}
	}
}

// TestFlowSiblingUploadAfterDroppedOverrun has stream 1 send a frame past its
// window and stream 3 then use the connection window the client was given, to
// a stock server and to a governed one: both take stream 3's body. The
// governor kept the dropped frame's connection credit, counted stream 3 past
// the connection window, and closed the connection.
func TestFlowSiblingUploadAfterDroppedOverrun(t *testing.T) {
	run := func(t *testing.T, governed bool) error {
		unblock1 := make(chan struct{})
		defer close(unblock1)
		bumpReady := make(chan struct{})
		startRead3 := make(chan struct{})
		bumpDone := make(chan error, 1)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/bump" {
				buf := make([]byte, 64<<10)
				if _, err := io.ReadFull(r.Body, buf); err != nil {
					bumpDone <- err
					return
				}
				close(bumpReady)
				<-startRead3
				rest := make([]byte, 256<<10)
				_, err := io.ReadFull(r.Body, rest)
				bumpDone <- err
				return
			}
			<-unblock1
		})

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		var listener net.Listener = ln
		h2cfg := &http.HTTP2Config{
			MaxReceiveBufferPerStream:     flowShownUp,
			MaxReceiveBufferPerConnection: flowConnFloor + 256<<10,
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
		srv := &http.Server{Handler: handler, Protocols: protocols, HTTP2: h2cfg}
		go srv.Serve(listener)
		defer srv.Close()

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(h2Preface))
		fr := http2.NewFramer(conn, conn)
		fr.WriteSettings()
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
		for _, kv := range [][2]string{{":method", "POST"}, {":scheme", "http"}, {":path", "/upload"}, {":authority", "example.com"}} {
			enc1.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
		}
		enc3 := hpack.NewEncoder(&hb3)
		for _, kv := range [][2]string{{":method", "POST"}, {":scheme", "http"}, {":path", "/bump"}, {":authority", "example.com"}} {
			enc3.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
		}
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb1.Bytes(), EndHeaders: true})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: hb3.Bytes(), EndHeaders: true})
		for i := 0; i < 4; i++ {
			fr.WriteData(3, false, make([]byte, 16384))
		}
		<-bumpReady

		ping1 := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		fr.WritePing(false, ping1)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == ping1 {
				break
			}
		}

		chunk := make([]byte, 16384)
		for sent := 0; sent < flowShownUp; sent += len(chunk) {
			fr.WriteData(1, false, chunk)
		}
		fr.WriteData(1, false, chunk) // 16 KiB past stream 1's 1 MiB window

		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if rst, ok := f.(*http2.RSTStreamFrame); ok && rst.StreamID == 1 {
				break
			}
		}

		for i := 0; i < 16; i++ {
			if err := fr.WriteData(3, i == 15, chunk); err != nil {
				close(startRead3)
				return err
			}
		}
		ping2 := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
		fr.WritePing(false, ping2)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				close(startRead3)
				return err
			}
			if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == ping2 {
				break
			}
		}
		close(startRead3)
		return <-bumpDone
	}

	stockErr := run(t, false)
	govErr := run(t, true)
	t.Logf("stream 3 256 KiB upload after stream 1 overrun -> stock err: %v; governed err: %v", stockErr, govErr)
	if stockErr != nil || govErr != nil {
		t.Fatalf("stockErr=%v, govErr=%v (want both nil)", stockErr, govErr)
	}
}

// TestFlowSiblingUploadAfterReadingStreamOverrun is
// TestFlowSiblingUploadAfterDroppedOverrun with stream 1 read in part before
// it sends past its window: stock and governed both take stream 3's body.
// The governor's release after the drop gave nothing back once stream 1 had
// read, and stream 3 closed the connection.
func TestFlowSiblingUploadAfterReadingStreamOverrun(t *testing.T) {
	run := func(t *testing.T, governed bool) error {
		unblock1 := make(chan struct{})
		defer close(unblock1)
		read64Ready := make(chan struct{})
		startRead3 := make(chan struct{})
		siblingDone := make(chan error, 1)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/sibling" {
				<-startRead3
				rest := make([]byte, 320<<10)
				_, err := io.ReadFull(r.Body, rest)
				siblingDone <- err
				return
			}
			buf := make([]byte, 64<<10)
			if _, err := io.ReadFull(r.Body, buf); err != nil {
				return
			}
			close(read64Ready)
			<-unblock1
		})

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		var listener net.Listener = ln
		// After reading 64 KiB on stream 1, stock has 960 KiB stream window left (total 1 MiB)
		// and 1280 KiB connection window left, matching governed's advertised windows.
		h2cfg := &http.HTTP2Config{
			MaxReceiveBufferPerStream:     flowShownUp - (64 << 10),
			MaxReceiveBufferPerConnection: flowConnFloor + 256<<10,
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
		srv := &http.Server{Handler: handler, Protocols: protocols, HTTP2: h2cfg}
		go srv.Serve(listener)
		defer srv.Close()

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(h2Preface))
		fr := http2.NewFramer(conn, conn)
		fr.WriteSettings()
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

		encodeHeaders := func(path string) []byte {
			var hb bytes.Buffer
			enc := hpack.NewEncoder(&hb)
			for _, kv := range [][2]string{
				{":method", "POST"},
				{":scheme", "http"},
				{":path", path},
				{":authority", "example.com"},
			} {
				enc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
			}
			return hb.Bytes()
		}

		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: encodeHeaders("/upload"), EndHeaders: true})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: encodeHeaders("/sibling"), EndHeaders: true})

		chunk := make([]byte, 16384)
		for i := 0; i < 4; i++ {
			fr.WriteData(1, false, chunk)
		}
		<-read64Ready

		ping1 := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		fr.WritePing(false, ping1)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == ping1 {
				break
			}
		}

		// Stream 1 sends the remaining 960 KiB of its 1 MiB window, plus 16 KiB past it.
		for sent := 64 << 10; sent < flowShownUp; sent += len(chunk) {
			fr.WriteData(1, false, chunk)
		}
		fr.WriteData(1, false, chunk) // 16 KiB past stream 1's window

		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if rst, ok := f.(*http2.RSTStreamFrame); ok && rst.StreamID == 1 {
				break
			}
		}

		// Stream 3 sends the remaining 320 KiB (20 * 16 KiB) of the connection window granted to the client.
		for i := 0; i < 20; i++ {
			if err := fr.WriteData(3, i == 19, chunk); err != nil {
				close(startRead3)
				return err
			}
		}
		ping2 := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
		fr.WritePing(false, ping2)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				close(startRead3)
				return err
			}
			if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == ping2 {
				break
			}
		}
		close(startRead3)
		return <-siblingDone
	}

	stockErr := run(t, false)
	govErr := run(t, true)
	t.Logf("two-stream self-read overrun -> stockErr=%v, govErr=%v", stockErr, govErr)
	if stockErr != nil || govErr != nil {
		t.Fatalf("stockErr=%v, govErr=%v (want both nil)", stockErr, govErr)
	}
}

// TestFlowSiblingUploadAfterFinishedStreamOverrun has stream 3 widen the
// connection window and finish before stream 1 sends past its window, and
// stream 5 then upload within the connection window: stock and governed both
// take stream 5's body.
func TestFlowSiblingUploadAfterFinishedStreamOverrun(t *testing.T) {
	run := func(t *testing.T, governed bool) error {
		unblock1 := make(chan struct{})
		defer close(unblock1)
		bumpReady := make(chan struct{})
		startRead5 := make(chan struct{})
		siblingDone := make(chan error, 1)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/bump":
				buf := make([]byte, 64<<10)
				if _, err := io.ReadFull(r.Body, buf); err != nil {
					return
				}
				close(bumpReady)
				io.Copy(io.Discard, r.Body)
			case "/sibling":
				<-startRead5
				rest := make([]byte, 256<<10)
				_, err := io.ReadFull(r.Body, rest)
				siblingDone <- err
			default:
				<-unblock1
			}
		})

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		var listener net.Listener = ln
		h2cfg := &http.HTTP2Config{
			MaxReceiveBufferPerStream:     flowShownUp,
			MaxReceiveBufferPerConnection: flowConnFloor + 256<<10,
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
		srv := &http.Server{Handler: handler, Protocols: protocols, HTTP2: h2cfg}
		go srv.Serve(listener)
		defer srv.Close()

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(h2Preface))
		fr := http2.NewFramer(conn, conn)
		fr.WriteSettings()
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

		encodeHeaders := func(path string) []byte {
			var hb bytes.Buffer
			enc := hpack.NewEncoder(&hb)
			for _, kv := range [][2]string{
				{":method", "POST"},
				{":scheme", "http"},
				{":path", path},
				{":authority", "example.com"},
			} {
				enc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
			}
			return hb.Bytes()
		}

		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: encodeHeaders("/upload"), EndHeaders: true})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: encodeHeaders("/bump"), EndHeaders: true})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 5, BlockFragment: encodeHeaders("/sibling"), EndHeaders: true})

		chunk := make([]byte, 16384)
		for i := 0; i < 4; i++ {
			fr.WriteData(3, false, chunk)
		}
		<-bumpReady

		ping0 := [8]byte{0, 1, 2, 3, 4, 5, 6, 7}
		fr.WritePing(false, ping0)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == ping0 {
				break
			}
		}

		// Stream 3 finishes its upload (END_STREAM).
		fr.WriteData(3, true, nil)

		ping1 := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		fr.WritePing(false, ping1)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == ping1 {
				break
			}
		}

		// Stream 1 sends 1 MiB + 16 KiB (overrunning its 1 MiB stream window).
		for sent := 0; sent < flowShownUp; sent += len(chunk) {
			fr.WriteData(1, false, chunk)
		}
		fr.WriteData(1, false, chunk) // 16 KiB past stream 1's 1 MiB window

		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if rst, ok := f.(*http2.RSTStreamFrame); ok && rst.StreamID == 1 {
				break
			}
		}

		// Stream 5 now sends 256 KiB, within the connection window that was already granted.
		for i := 0; i < 16; i++ {
			if err := fr.WriteData(5, i == 15, chunk); err != nil {
				close(startRead5)
				return err
			}
		}
		ping2 := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
		fr.WritePing(false, ping2)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				close(startRead5)
				return err
			}
			if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == ping2 {
				break
			}
		}
		close(startRead5)
		return <-siblingDone
	}

	stockErr := run(t, false)
	govErr := run(t, true)
	t.Logf("stockErr=%v, govErr=%v", stockErr, govErr)
	if stockErr != nil || govErr != nil {
		t.Fatalf("stockErr=%v, govErr=%v (want both nil)", stockErr, govErr)
	}
}

// TestFlowDataInHeaderBlockAsStock sends a DATA frame past the stream's window
// inside an open header block: the governed server ends the connection as a
// stock one does. The governor dropped the frame and reset the stream, and
// the stack never saw the protocol error.
func TestFlowDataInHeaderBlockAsStock(t *testing.T) {
	run := func(t *testing.T, governed bool) (gotGoAway bool, errCode http2.ErrCode) {
		unblock := make(chan struct{})
		defer close(unblock)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/bump" {
				io.Copy(io.Discard, r.Body)
				return
			}
			<-unblock
		})

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		var listener net.Listener = ln
		h2cfg := &http.HTTP2Config{
			MaxReceiveBufferPerStream:     flowShownUp,
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
		srv := &http.Server{Handler: handler, Protocols: protocols, HTTP2: h2cfg}
		go srv.Serve(listener)
		defer srv.Close()

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(h2Preface))
		fr := http2.NewFramer(conn, conn)
		fr.WriteSettings()
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
		for _, kv := range [][2]string{{":method", "POST"}, {":scheme", "http"}, {":path", "/upload"}, {":authority", "example.com"}} {
			enc1.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
		}
		enc3 := hpack.NewEncoder(&hb3)
		for _, kv := range [][2]string{{":method", "POST"}, {":scheme", "http"}, {":path", "/bump"}, {":authority", "example.com"}} {
			enc3.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
		}
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb1.Bytes(), EndHeaders: true})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: hb3.Bytes(), EndHeaders: true})
		for i := 0; i < 4; i++ {
			fr.WriteData(3, false, make([]byte, 16384))
		}
		connWin := int64(h2InitWindow) - 4*16384
		for connWin < int64(flowShownUp)+16384 {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if wu, ok := f.(*http2.WindowUpdateFrame); ok && wu.StreamID == 0 {
				connWin += int64(wu.Increment)
			}
		}

		chunk := make([]byte, 16384)
		for sent := 0; sent < flowShownUp; sent += len(chunk) {
			fr.WriteData(1, false, chunk)
		}
		// Start a trailer HEADERS block without END_HEADERS (p.inBlock = true),
		// then send a DATA frame that exceeds stream 1's window.
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb1.Bytes(), EndHeaders: false})
		fr.WriteData(1, false, make([]byte, 100))

		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return gotGoAway, errCode
			}
			if ga, ok := f.(*http2.GoAwayFrame); ok {
				return true, ga.ErrCode
			}
		}
	}

	stockGA, stockCode := run(t, false)
	govGA, govCode := run(t, true)
	t.Logf("data inside header block -> stock: goAway=%v code=%v; governed: goAway=%v code=%v",
		stockGA, stockCode, govGA, govCode)
	if govGA != stockGA || govCode != stockCode {
		t.Fatalf("governed (goAway=%v, code=%v) differs from stock (goAway=%v, code=%v)",
			govGA, govCode, stockGA, stockCode)
	}
}
