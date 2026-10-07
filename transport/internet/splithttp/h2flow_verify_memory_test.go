package splithttp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

// rawH2Client is a greedy HTTP/2 client: it sends DATA on its streams as far
// as the server's credit allows and counts every byte the server accepted.
type rawH2Client struct {
	t        *testing.T
	conn     net.Conn
	fr       *http2.Framer
	init     int64
	connWin  int64
	streams  map[uint32]int64
	accepted int64
}

func dialRawH2(t *testing.T, addr string) *rawH2Client {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &rawH2Client{t: t, conn: conn, fr: http2.NewFramer(conn, conn), init: h2InitWindow, connWin: h2InitWindow, streams: map[uint32]int64{}}
	c.fr.SetMaxReadFrameSize(1 << 24)
	if _, err := conn.Write([]byte(h2Preface)); err != nil {
		t.Fatal(err)
	}
	if err := c.fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	return c
}

// rawPostHeaders is a minimal header block: :method POST, :scheme http, :path /,
// :authority x (literal without indexing).
var rawPostHeaders = []byte{0x83, 0x86, 0x84, 0x01, 0x01, 'x'}

func (c *rawH2Client) open(id uint32) {
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: rawPostHeaders, EndHeaders: true}); err != nil {
		c.t.Fatal(err)
	}
	c.streams[id] = c.init
}

// pump reads what the server sends and spends all credit until nothing has
// moved for quiet.
func (c *rawH2Client) pump(quiet time.Duration) {
	last := time.Now()
	chunk := make([]byte, h2MinMaxFrameSize)
	for time.Since(last) < quiet {
		for id, w := range c.streams {
			for w > 0 && c.connWin > 0 {
				n := min(w, c.connWin, int64(len(chunk)))
				if err := c.fr.WriteData(id, false, chunk[:n]); err != nil {
					c.t.Fatal(err)
				}
				w -= n
				c.connWin -= n
				c.accepted += n
				last = time.Now()
			}
			c.streams[id] = w
		}
		c.conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		f, err := c.fr.ReadFrame()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			c.t.Fatalf("read: %v", err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
				for id := range c.streams {
					c.streams[id] += int64(v) - c.init
				}
				c.init = int64(v)
			}
			c.fr.WriteSettingsAck()
		case *http2.PingFrame:
			if !f.IsAck() {
				c.fr.WritePing(true, f.Data)
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				c.connWin += int64(f.Increment)
			} else if _, ok := c.streams[f.StreamID]; ok {
				c.streams[f.StreamID] += int64(f.Increment)
			}
			last = time.Now()
		}
	}
}

// TestFlowServerUnreadPerConnection (added for bdbac60e) opens 32 upload
// streams whose handlers never read and counts what the server accepts on
// the connection. Stock Go holds that to its 1 MiB connection window; the
// PR states that a governed server reaches its 6 MiB only "while the outbound
// keeps up" and that behind a proxy or without TCP_INFO windows never exceed
// Go's 1 MiB. Neither holds for the connection: the governor caps streams,
// not their sum.
func TestFlowServerUnreadPerConnection(t *testing.T) {
	results := map[bool]int64{}
	for _, governed := range []bool{false, true} {
		t.Run(fmt.Sprintf("governed=%v", governed), func(t *testing.T) {
			saved := flowEnabled
			flowEnabled = governed
			defer func() { flowEnabled = saved }()
			block := make(chan struct{})
			defer close(block)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var listener net.Listener = ln
			cfg := &Config{}
			if cfg.h2FlowOn() {
				listener = &flowListener{Listener: ln, up: flowDefault, down: flowDefault}
			}
			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			protocols.SetUnencryptedHTTP2(true)
			srv := &http.Server{
				Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }),
				Protocols: protocols,
				HTTP2:     cfg.h2ReceiveConfig(true),
			}
			go srv.Serve(listener)
			defer srv.Close()

			c := dialRawH2(t, ln.Addr().String())
			for i := uint32(0); i < 32; i++ {
				c.open(2*i + 1)
			}
			c.pump(time.Second)
			results[governed] = c.accepted
			t.Logf("server accepted %d bytes on 32 streams nobody reads", c.accepted)
		})
	}
	if results[true] > 1<<20+64<<10 {
		t.Fatalf("governed server holds %d unread bytes on one connection, stock %d (Go's 1 MiB)", results[true], results[false])
	}
}

// blockingListener shrinks the send buffer of accepted connections so a
// client that stops reading blocks the server's writes after a few KiB.
type blockingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []*flowConn
	wrap  bool
}

func (l *blockingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c.(*net.TCPConn).SetWriteBuffer(4096)
	if !l.wrap {
		return c, nil
	}
	fc := newFlowConn(c, flowDefault, flowDefault)
	l.mu.Lock()
	l.conns = append(l.conns, fc)
	l.mu.Unlock()
	return fc, nil
}

// TestFlowInjectedQueueBounded (added for bdbac60e) stops reading on the
// client so the server's writes block, then opens and resets streams. Every
// new stream makes the governor queue a WINDOW_UPDATE for the client in
// wqueue, outside net/http's own control-frame limit, and nothing drains it
// while the write is blocked: the queue grows with what the client sends.
func TestFlowInjectedQueueBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bl := &blockingListener{Listener: ln, wrap: true}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }),
		Protocols: protocols,
		HTTP2:     (&Config{H2Flow: &H2FlowConfig{Mode: 1}}).h2ReceiveConfig(true),
	}
	go srv.Serve(bl)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(*net.TCPConn).SetReadBuffer(4096)
	var b bytes.Buffer
	fr := http2.NewFramer(&b, nil)
	b.WriteString(h2Preface)
	fr.WriteSettings()
	// PINGs the server answers until its writes block; well under net/http's
	// limit of 10000 queued control frames.
	for i := 0; i < 3000; i++ {
		fr.WritePing(false, [8]byte{byte(i), byte(i >> 8)})
	}
	if _, err := conn.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	queued := func() (n int, blocked bool) {
		bl.mu.Lock()
		defer bl.mu.Unlock()
		for _, c := range bl.conns {
			c.mu.Lock()
			n += queuedBytes(c)
			c.mu.Unlock()
			if c.wmu.TryLock() {
				c.wmu.Unlock()
			} else {
				blocked = true
			}
		}
		return
	}
	id := uint32(1)
	send := func(pairs int) {
		b.Reset()
		for i := 0; i < pairs; i++ {
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: rawPostHeaders, EndHeaders: true})
			fr.WriteRSTStream(id, http2.ErrCodeCancel)
			id += 2
		}
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(b.Bytes()); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}
	var sizes []int
	sent := 0
	for _, pairs := range []int{20000, 20000, 20000} {
		send(pairs)
		sent += pairs * (len(b.Bytes()) / pairs)
		time.Sleep(300 * time.Millisecond)
		n, blocked := queued()
		sizes = append(sizes, n)
		t.Logf("after %d client bytes: %d bytes queued in wqueue, server write blocked %v", sent, n, blocked)
	}
	if sizes[len(sizes)-1] > 64<<10 {
		t.Fatalf("wqueue holds %v bytes after the client sent %d bytes and stopped reading; it grows without bound", sizes, sent)
	}
}

// TestFlowProtoField32 (added for bdbac60e) checks the generated descriptor
// for the new field and a wire round trip.
func TestFlowProtoField32(t *testing.T) {
	fd := (&Config{}).ProtoReflect().Descriptor().Fields().ByNumber(32)
	if fd == nil || fd.Name() != "h2Flow" || fd.Message().FullName() != "xray.transport.internet.splithttp.H2FlowConfig" {
		t.Fatalf("field 32: %v", fd)
	}
	in := &Config{H2Flow: &H2FlowConfig{Mode: 1, MaxStreamReceiveWindow: 1 << 20, MaxConnectionReceiveWindow: 2 << 20}}
	raw, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := &Config{}
	if err := proto.Unmarshal(raw, out); err != nil || !proto.Equal(in, out) {
		t.Fatalf("round trip: %v, %v", out, err)
	}
}

// TestFlowInjectedQueueHeapVsStock (added for bdbac60e) runs the
// TestFlowInjectedQueueBounded client against a stock and a governed server
// and compares live heap growth after the stream churn, so the queue is not
// mistaken for memory net/http would hold anyway.
func TestFlowInjectedQueueHeapVsStock(t *testing.T) {
	if raceEnabled {
		t.Skip("heap growth under the race detector says nothing, and the churn outlasts its write deadlines")
	}
	// Measured on bdbac60e: stock grows ~2.7 MB at both 2 and 10 rounds
	// (bounded); governed grows ~3.3 MB at 2 rounds and ~7.6 MB at 10,
	// about 13.5 bytes per stream: the injected WINDOW_UPDATEs in wqueue.
	const churnRounds = 10
	growth := map[bool]int64{}
	for _, governed := range []bool{false, true} {
		t.Run(fmt.Sprintf("governed=%v", governed), func(t *testing.T) {
			// A stock server whose writes block stops reading once the
			// handlers it started cannot finish, depending on how the
			// resets interleave with them; that attempt says nothing about
			// the governor, so it is run again.
			attempt := func() bool {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				bl := &blockingListener{Listener: ln, wrap: governed}
				protocols := new(http.Protocols)
				protocols.SetHTTP1(true)
				protocols.SetUnencryptedHTTP2(true)
				mode := int32(2)
				if governed {
					mode = 1
				}
				srv := &http.Server{
					Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }),
					Protocols: protocols,
					HTTP2:     (&Config{H2Flow: &H2FlowConfig{Mode: mode}}).h2ReceiveConfig(true),
				}
				go srv.Serve(bl)
				defer srv.Close()
				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.(*net.TCPConn).SetReadBuffer(4096)
				var b bytes.Buffer
				fr := http2.NewFramer(&b, nil)
				b.WriteString(h2Preface)
				fr.WriteSettings()
				for i := 0; i < 3000; i++ {
					fr.WritePing(false, [8]byte{byte(i), byte(i >> 8)})
				}
				conn.Write(b.Bytes())
				time.Sleep(200 * time.Millisecond)
				heap := func() int64 {
					runtime.GC()
					var ms runtime.MemStats
					runtime.ReadMemStats(&ms)
					return int64(ms.HeapAlloc)
				}
				before := heap()
				id := uint32(1)
				for round := 0; round < churnRounds; round++ {
					b.Reset()
					for i := 0; i < 40000; i++ {
						fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: rawPostHeaders, EndHeaders: true})
						fr.WriteRSTStream(id, http2.ErrCodeCancel)
						id += 2
					}
					conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if _, err := conn.Write(b.Bytes()); err != nil {
						t.Logf("client write in round %d: %v; the server stopped reading", round, err)
						return false
					}
				}
				time.Sleep(500 * time.Millisecond)
				growth[governed] = heap() - before
				// The connection must still be up: probe with one more frame.
				b.Reset()
				fr.WritePing(false, [8]byte{9})
				_, werr := conn.Write(b.Bytes())
				t.Logf("%d streams opened and reset: live heap grew by %d bytes; connection still writable: %v", churnRounds*40000, growth[governed], werr == nil)
				return true
			}
			for i := 0; !attempt(); i++ {
				if i == 2 {
					// Slow instrumented builds (checkptr) stall every time.
					t.Skip("the server stopped reading in every attempt; heap not compared")
				}
			}
		})
	}
	if growth[true]-growth[false] > 1<<20 {
		t.Fatalf("governed server holds %d more live heap than stock after the same stream churn", growth[true]-growth[false])
	}
}
