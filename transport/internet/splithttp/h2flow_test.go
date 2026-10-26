package splithttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type passFrames struct{}

func (passFrames) frame(h2Frame) {}
func (passFrames) control(_ h2Frame, header, payload, out []byte) []byte {
	return append(append(out, header...), payload...)
}
func (passFrames) boundary(out []byte) []byte { return out }

func TestFrameParserChunking(t *testing.T) {
	var stream bytes.Buffer
	fr := http2.NewFramer(&stream, nil)
	fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	for i := uint32(1); i < 200; i += 2 {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: i, BlockFragment: []byte("abc"), EndHeaders: i%3 != 0})
		if i%3 == 0 {
			fr.WriteContinuation(i, true, []byte("def"))
		}
		payload := make([]byte, mrand.IntN(20000))
		fr.WriteData(i, i%5 == 0, payload)
		fr.WriteWindowUpdate(i, uint32(1+mrand.IntN(1<<20)))
		fr.WritePing(i%2 == 0, [8]byte{byte(i)})
		fr.WriteRSTStream(i, http2.ErrCodeCancel)
	}
	want := stream.Bytes()
	for round := 0; round < 50; round++ {
		var p frameParser
		var out []byte
		for in := want; len(in) > 0; {
			n := min(len(in), 1+mrand.IntN(64))
			out = p.feed(in[:n], out, passFrames{})
			in = in[n:]
		}
		if !bytes.Equal(out, want) {
			t.Fatalf("round %d: output differs from input", round)
		}
		if !p.atBoundary() {
			t.Fatal("parser not at a frame boundary after the whole stream")
		}
	}
}

// chaosConn splits reads and writes at random byte offsets.
type chaosConn struct {
	net.Conn
}

func (c chaosConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b[:1+mrand.IntN(len(b))])
}

func (c chaosConn) Write(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Conn.Write(b[n : n+min(len(b)-n, 1+mrand.IntN(4096))])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

type testListener struct {
	net.Listener
	chaos bool
	mu    sync.Mutex
	conns []*flowConn
	up    flowLimit
	down  flowLimit
	// sendWindow is given to the connections accepted from now on.
	sendWindow int64
}

func (l *testListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.chaos {
		c = chaosConn{c}
	}
	if !l.up.enabled() && !l.down.enabled() {
		return c, nil
	}
	fc := newFlowConn(c, l.up, l.down)
	l.mu.Lock()
	fc.sendWindow = l.sendWindow
	l.conns = append(l.conns, fc)
	l.mu.Unlock()
	return fc, nil
}

func (l *testListener) each(f func(c *flowConn)) {
	l.mu.Lock()
	conns := append([]*flowConn(nil), l.conns...)
	l.mu.Unlock()
	for _, c := range conns {
		c.mu.Lock()
		f(c)
		c.mu.Unlock()
	}
}

func startFlowServer(t *testing.T, up, down flowLimit, chaos bool, h http.Handler) (*testListener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := &testListener{Listener: ln, chaos: chaos, up: up, down: down}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: h, Protocols: protocols}
	go srv.Serve(tl)
	t.Cleanup(func() { srv.Close() })
	return tl, ln.Addr().String()
}

func h2Client(addr string) *http.Client {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{
		Protocols: protocols,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
}

var (
	testUp   = flowDefault
	testDown = flowDefault
)

func echoHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.(http.Flusher).Flush()
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		if err != nil {
			return
		}
	}
}

func TestFlowIntegrityDuplex(t *testing.T) {
	for _, chaos := range []bool{false, true} {
		_, addr := startFlowServer(t, testUp, testDown, chaos, http.HandlerFunc(echoHandler))
		client := h2Client(addr)
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				data := make([]byte, 1<<20+mrand.IntN(3<<20))
				rand.Read(data)
				pr, pw := io.Pipe()
				go func() {
					for off := 0; off < len(data); {
						n := min(len(data)-off, 1+mrand.IntN(64<<10))
						if _, err := pw.Write(data[off : off+n]); err != nil {
							return
						}
						off += n
					}
					pw.Close()
				}()
				req, _ := http.NewRequest("POST", "http://x/echo", pr)
				resp, err := client.Do(req)
				if err != nil {
					errs <- err
					return
				}
				defer resp.Body.Close()
				got, err := io.ReadAll(resp.Body)
				if err != nil {
					errs <- err
					return
				}
				if sha256.Sum256(got) != sha256.Sum256(data) {
					errs <- io.ErrShortBuffer
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("chaos=%v: %v", chaos, err)
		}
	}
}

// slowCopy reads r at about rate bytes per second, counting what it consumed.
func slowCopy(r io.Reader, rate int, consumed *atomic.Int64, stop <-chan struct{}) {
	buf := make([]byte, 8<<10)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		for want := rate / 100; want > 0; {
			n, err := r.Read(buf[:min(want, len(buf))])
			consumed.Add(int64(n))
			want -= n
			if err != nil {
				return
			}
		}
	}
}

func TestFlowSlowDownlinkReaderBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		down flowLimit
		max  int64
	}{
		{"governed", testDown, int64(testDown.init) + 64<<10},
		{"stock", flowLimit{}, 0},
	} {
		var written atomic.Int64
		tl, addr := startFlowServer(t, flowLimit{}, tc.down, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, 16<<10)
			for {
				n, err := w.Write(buf)
				written.Add(int64(n))
				if err != nil {
					return
				}
			}
		}))
		resp, err := h2Client(addr).Get("http://x/down")
		if err != nil {
			t.Fatal(err)
		}
		var consumed atomic.Int64
		stop := make(chan struct{})
		go slowCopy(resp.Body, 256<<10, &consumed, stop)
		time.Sleep(3 * time.Second)
		var unread int64
		tl.each(func(c *flowConn) {
			for _, s := range c.streams {
				unread = max(unread, s.downSent-s.down.returned)
			}
		})
		gap := written.Load() - consumed.Load()
		close(stop)
		resp.Body.Close()
		t.Logf("%s: server wrote %d, client read %d, gap %d, unread at client %d", tc.name, written.Load(), consumed.Load(), gap, unread)
		if tc.max > 0 && unread > tc.max {
			t.Fatalf("%s: unread at client %d exceeds %d", tc.name, unread, tc.max)
		}
		if tc.max > 0 && gap > tc.max+256<<10 {
			t.Fatalf("%s: gap %d between written and read is too large", tc.name, gap)
		}
	}
}

func TestFlowSlowUplinkHandlerBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		up   flowLimit
		max  int64
	}{
		// The client may send the 1 MiB a governed server shows at once;
		// stock lets the handler fall a whole MiB behind on every round.
		{"governed", testUp, int64(flowShownUp) + 64<<10},
		{"stock", flowLimit{}, 0},
	} {
		var consumed atomic.Int64
		stop := make(chan struct{})
		tl, addr := startFlowServer(t, tc.up, flowLimit{}, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slowCopy(r.Body, 256<<10, &consumed, stop)
		}))
		var written atomic.Int64
		pr, pw := io.Pipe()
		go func() {
			buf := make([]byte, 16<<10)
			for {
				n, err := pw.Write(buf)
				written.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
		req, _ := http.NewRequest("POST", "http://x/up", pr)
		client := h2Client(addr)
		done := make(chan struct{})
		go func() {
			defer close(done)
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
		}()
		time.Sleep(3 * time.Second)
		var unread int64
		tl.each(func(c *flowConn) {
			for _, s := range c.streams {
				unread = max(unread, s.upSent-s.up.returned)
			}
		})
		t.Logf("%s: client wrote %d, handler read %d, gap %d, unread at server %d", tc.name, written.Load(), consumed.Load(), written.Load()-consumed.Load(), unread)
		close(stop)
		pw.CloseWithError(io.ErrClosedPipe)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("%s: upload request still running after its body was closed", tc.name)
		}
		client.CloseIdleConnections()
		if tc.max > 0 && unread > tc.max {
			t.Fatalf("%s: unread at server %d exceeds %d", tc.name, unread, tc.max)
		}
	}
}

type parcel struct {
	dst net.Conn
	b   []byte
	at  time.Time
}

// fifoLink is one direction of a shared bottleneck: every connection's bytes
// wait in a single FIFO, delayed and then serialised at a fixed rate.
type fifoLink struct {
	ch  chan parcel
	bps float64
}

func newFifoLink(mbit float64) *fifoLink {
	l := &fifoLink{ch: make(chan parcel, 1<<16), bps: mbit * 1e6 / 8}
	go func() {
		next := time.Now()
		for p := range l.ch {
			time.Sleep(time.Until(p.at))
			if now := time.Now(); next.Before(now) {
				next = now
			}
			next = next.Add(time.Duration(float64(len(p.b)) / l.bps * float64(time.Second)))
			time.Sleep(time.Until(next))
			p.dst.Write(p.b)
		}
	}()
	return l
}

// lagProxy delays every chunk by a fixed one-way delay in both directions.
func lagProxy(t *testing.T, backend string, delay time.Duration) string {
	return shapedProxy(t, backend, delay, 0)
}

// shapedProxy is lagProxy whose downlink (backend to client) is a FIFO
// bottleneck of mbit shared by every connection through it.
func shapedProxy(t *testing.T, backend string, delay time.Duration, mbit float64) string {
	var down *fifoLink
	if mbit > 0 {
		down = newFifoLink(mbit)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pipe := func(dst, src net.Conn, link *fifoLink) {
		ch := make(chan parcel, 1<<14)
		if link != nil {
			ch = link.ch
		}
		buf := make([]byte, 16<<10)
		if link == nil {
			go func() {
				for p := range ch {
					time.Sleep(time.Until(p.at))
					if _, err := p.dst.Write(p.b); err != nil {
						break
					}
				}
				dst.Close()
			}()
		}
		for {
			n, err := src.Read(buf)
			if n > 0 {
				ch <- parcel{dst, append([]byte(nil), buf[:n]...), time.Now().Add(delay)}
			}
			if err != nil {
				if link == nil {
					close(ch)
				} else {
					dst.Close()
				}
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", backend)
			if err != nil {
				c.Close()
				continue
			}
			go pipe(s, c, nil)
			go pipe(c, s, down)
		}
	}()
	return ln.Addr().String()
}

// measure returns the steady-state rate over the second half of a long
// transfer and the time the first 4 MiB took, both through a lagged path.
func measure(t *testing.T, up, down flowLimit, rtt time.Duration, upload bool) (float64, time.Duration) {
	const size = 64 << 20
	var got atomic.Int64
	var first4, half time.Time
	var mark sync.Once
	var markHalf sync.Once
	note := func(start time.Time) {
		if got.Load() >= 4<<20 {
			mark.Do(func() { first4 = time.Now() })
		}
		if got.Load() >= size/2 {
			markHalf.Do(func() { half = time.Now() })
		}
	}
	var start time.Time
	_, addr := startFlowServer(t, up, down, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			buf := make([]byte, 32<<10)
			for {
				n, err := r.Body.Read(buf)
				got.Add(int64(n))
				note(start)
				if err != nil {
					return
				}
			}
		}
		buf := make([]byte, 32<<10)
		for sent := 0; sent < size; sent += len(buf) {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	client := h2Client(lagProxy(t, addr, rtt/2))
	if resp, err := client.Get("http://x/warm"); err == nil {
		resp.Body.Read(make([]byte, 1))
		resp.Body.Close()
	}
	start = time.Now()
	if upload {
		req, _ := http.NewRequest("POST", "http://x/up", io.LimitReader(zeroReader{}, size))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	} else {
		resp, err := client.Get("http://x/down")
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			got.Add(int64(n))
			note(start)
			if err != nil {
				break
			}
		}
		resp.Body.Close()
		if got.Load() != size {
			t.Fatalf("downloaded %d of %d", got.Load(), size)
		}
	}
	end := time.Now()
	return float64(size/2) / end.Sub(half).Seconds() / (1 << 20), first4.Sub(start)
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}

func TestFlowFastReaderKeepsThroughput(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing-sensitive")
	}
	rtt := 40 * time.Millisecond
	for _, upload := range []bool{false, true} {
		base, baseRamp := measure(t, flowLimit{}, flowLimit{}, rtt, upload)
		gov, govRamp := measure(t, testUp, testDown, rtt, upload)
		t.Logf("upload=%v rtt=%v: steady stock %.1f MiB/s, governed %.1f MiB/s; first 4 MiB stock %v, governed %v",
			upload, rtt, base, gov, baseRamp.Round(time.Millisecond), govRamp.Round(time.Millisecond))
		if gov < base*0.85 {
			t.Fatalf("upload=%v: governed steady throughput %.1f is below 85%% of stock %.1f", upload, gov, base)
		}
	}
}

func TestFlowStreamStateReleased(t *testing.T) {
	tl, addr := startFlowServer(t, testUp, testDown, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hang":
			<-r.Context().Done()
		default:
			io.Copy(io.Discard, r.Body)
			w.Write(make([]byte, 100<<10))
		}
	}))
	client := h2Client(addr)
	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				resp, err := client.Post("http://x/ok", "", bytes.NewReader(make([]byte, 64<<10)))
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			case 1:
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, "GET", "http://x/hang", nil)
				if resp, err := client.Do(req); err == nil {
					resp.Body.Close()
				}
			case 2:
				resp, err := client.Get("http://x/ok")
				if err == nil {
					resp.Body.Read(make([]byte, 100))
					resp.Body.Close()
				}
			}
		}(i)
	}
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		left := 0
		tl.each(func(c *flowConn) { left += len(c.streams) })
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d stream states left after all requests finished", left)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestFlowMeasuresRTT(t *testing.T) {
	tl, addr := startFlowServer(t, testUp, testDown, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 30; i++ {
			w.Write(make([]byte, 32<<10))
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	resp, err := h2Client(lagProxy(t, addr, 25*time.Millisecond)).Get("http://x/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	var rtt time.Duration
	tl.each(func(c *flowConn) { rtt = max(rtt, c.currentRTT()) })
	t.Logf("measured rtt %v", rtt)
	if rtt < 40*time.Millisecond || rtt > 200*time.Millisecond {
		t.Fatalf("rtt %v is off the 50ms path", rtt)
	}
}

func TestFlowPlainHTTP1PassesThrough(t *testing.T) {
	_, addr := startFlowServer(t, testUp, testDown, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write(b)
	}))
	body := make([]byte, 200<<10)
	rand.Read(body)
	resp, err := (&http.Client{Transport: &http.Transport{}}).Post("http://"+addr+"/", "", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 1 || !bytes.Equal(got, body) {
		t.Fatalf("HTTP/1.1 round trip broken: proto %s, %d bytes", resp.Proto, len(got))
	}
}

func TestRewriteInitialWindow(t *testing.T) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload, 0x3)
	binary.BigEndian.PutUint32(payload[2:], 100)
	binary.BigEndian.PutUint16(payload[6:], h2SettingInitialWindowSize)
	binary.BigEndian.PutUint32(payload[8:], 4<<20)
	real, shown, ok := rewriteInitialWindow(payload, 256<<10)
	if !ok || real != 4<<20 || shown != 256<<10 || binary.BigEndian.Uint32(payload[8:]) != 256<<10 || binary.BigEndian.Uint32(payload[2:]) != 100 {
		t.Fatalf("got real %d shown %d ok %v", real, shown, ok)
	}
}

func latencyUnderBulk(t *testing.T, up, down flowLimit, sameConn bool) (p50, p95 time.Duration) {
	_, addr := startFlowServer(t, up, down, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.Write([]byte("pong"))
			return
		}
		buf := make([]byte, 16<<10)
		for {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	proxy := shapedProxy(t, addr, 20*time.Millisecond, 40)
	bulkClient := h2Client(proxy)
	pingClient := bulkClient
	if !sameConn {
		pingClient = h2Client(proxy)
	}
	resp, err := bulkClient.Get("http://x/bulk")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	go io.Copy(io.Discard, resp.Body)
	time.Sleep(2 * time.Second)
	var lat []time.Duration
	for i := 0; i < 30; i++ {
		start := time.Now()
		r, err := pingClient.Get("http://x/ping")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		lat = append(lat, time.Since(start))
		time.Sleep(50 * time.Millisecond)
	}
	slices.Sort(lat)
	return lat[len(lat)/2], lat[len(lat)*95/100]
}

func TestFlowLatencyUnderBulk(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	for _, same := range []bool{true, false} {
		s50, s95 := latencyUnderBulk(t, flowLimit{}, flowLimit{}, same)
		g50, g95 := latencyUnderBulk(t, testUp, testDown, same)
		t.Logf("same connection %v: small request p50/p95 stock %v/%v, governed %v/%v", same,
			s50.Round(time.Millisecond), s95.Round(time.Millisecond), g50.Round(time.Millisecond), g95.Round(time.Millisecond))
		if g95 > s95 {
			t.Fatalf("same connection %v: governed p95 %v is worse than stock %v", same, g95, s95)
		}
	}
}

func TestFlowChurnLeaves(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	before := runtime.NumGoroutine()
	tl, addr := startFlowServer(t, testUp, testDown, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			echoHandler(w, r)
		case "/hang":
			<-r.Context().Done()
		default:
			w.Write(make([]byte, mrand.IntN(256<<10)))
		}
	}))
	for round := 0; round < 5; round++ {
		client := h2Client(addr)
		var wg sync.WaitGroup
		for i := 0; i < 400; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1+mrand.IntN(200))*time.Millisecond)
				defer cancel()
				var req *http.Request
				switch i % 4 {
				case 0:
					req, _ = http.NewRequestWithContext(ctx, "POST", "http://x/echo", io.LimitReader(zeroReader{}, int64(mrand.IntN(1<<20))))
				case 1:
					req, _ = http.NewRequestWithContext(ctx, "GET", "http://x/hang", nil)
				default:
					req, _ = http.NewRequestWithContext(ctx, "GET", "http://x/get", nil)
				}
				if resp, err := client.Do(req); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}(i)
		}
		wg.Wait()
		client.CloseIdleConnections()
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		left := 0
		tl.each(func(c *flowConn) {
			if !c.closed {
				left += len(c.streams) + queuedBytes(c) + len(c.opened)
			}
		})
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			kinds := map[string]int{}
			tl.each(func(c *flowConn) {
				if c.closed {
					return
				}
				for _, st := range c.streams {
					kinds[fmt.Sprintf("clientDone=%v serverDone=%v up=%d down=%d", st.clientDone, st.serverDone, st.upSent, st.downSent)]++
				}
			})
			t.Fatalf("%d stream states or queued frames left: %v", left, kinds)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// A snapshot can catch a goroutine that is only passing through a lock
	// under load; one that is stuck shows up in every snapshot.
	buf := make([]byte, 4<<20)
	stuck := ""
	for range 3 {
		stuck = ""
		for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if strings.Contains(g, "(*flowConn)") && (strings.Contains(g, "semacquire") || strings.Contains(g, "sync.(*Mutex)")) {
				stuck = g
				break
			}
		}
		if stuck == "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if stuck != "" {
		t.Fatalf("goroutine stuck in the governor after all requests finished:\n%s", stuck)
	}
	t.Logf("goroutines %d before, %d after (idle server connections included)", before, runtime.NumGoroutine())
}

func TestFlowLearnedDecays(t *testing.T) {
	now := time.Now()
	var l flowLearned
	const init = 256 << 10
	if v := l.value(now, init); v != init {
		t.Fatalf("empty: %d", v)
	}
	l.note(now, init, 4<<20)
	for _, tc := range []struct {
		after time.Duration
		want  int32
	}{
		{0, 4 << 20},
		{flowLearnHalf - time.Millisecond, 4 << 20},
		{flowLearnHalf, init + (4<<20-init)/2},
		{2 * flowLearnHalf, init + (4<<20-init)/4},
		{time.Hour, init},
	} {
		if v := l.value(now.Add(tc.after), init); v != tc.want {
			t.Fatalf("after %v: %d, want %d", tc.after, v, tc.want)
		}
	}
	l.note(now.Add(2*flowLearnHalf), init, 512<<10)
	if v := l.value(now.Add(2*flowLearnHalf), init); v != init+(4<<20-init)/4 {
		t.Fatalf("a smaller cap must not replace a larger decayed one: %d", v)
	}
	l.note(now.Add(time.Hour), init, 512<<10)
	if v := l.value(now.Add(time.Hour), init); v != 512<<10 {
		t.Fatalf("a fresh cap after full decay: %d", v)
	}
}

// batchingGet downloads size bytes over a raw HTTP/2 connection whose client
// advertises window and hands credit back only once half of it is consumed,
// the way nghttp2 and Chromium do.
func batchingGet(t *testing.T, addr string, window uint32, size int) (int, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	io.WriteString(conn, http2.ClientPreface)
	fr := http2.NewFramer(conn, conn)
	fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window})
	fr.WriteWindowUpdate(0, 1<<30)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "x"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true})
	got, unsent := 0, 0
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return got, err
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				fr.WritePing(true, f.Data)
			}
		case *http2.DataFrame:
			got += len(f.Data())
			unsent += int(f.Length)
			if unsent >= int(window)/2 {
				fr.WriteWindowUpdate(1, uint32(unsent))
				unsent = 0
			}
			if f.StreamEnded() {
				return got, nil
			}
		}
	}
}

func TestFlowBatchingClientDoesNotStall(t *testing.T) {
	const size = 24 << 20
	_, addr := startFlowServer(t, flowLimit{}, testDown, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32<<10)
		for sent := 0; sent < size; sent += len(buf) {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	for _, window := range []uint32{1 << 20, 4 << 20, 16 << 20} {
		start := time.Now()
		got, err := batchingGet(t, addr, window, size)
		if got != size {
			t.Fatalf("window %d: got %d of %d bytes (%v) after %v", window, got, size, err, time.Since(start))
		}
		t.Logf("window %d MiB: %d MiB in %v", window>>20, size>>20, time.Since(start).Round(time.Millisecond))
	}
}

// stallConn is a socket that hands the governor only what the test feeds it:
// Read waits for the next chunk, and Write, while stalled, waits as a socket
// whose peer stopped reading does. Both give up once the socket is closed.
type stallConn struct {
	net.Conn
	in      chan []byte
	pending []byte
	closed  chan struct{}
	once    sync.Once
	stalled atomic.Bool
	mu      sync.Mutex
	out     bytes.Buffer
}

func newStallConn() *stallConn {
	return &stallConn{in: make(chan []byte, 16), closed: make(chan struct{})}
}

func (c *stallConn) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		select {
		case c.pending = <-c.in:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *stallConn) Write(b []byte) (int, error) {
	if c.stalled.Load() {
		<-c.closed
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(b)
}

func (c *stallConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// within fails the test with the stacks of all goroutines unless f returns
// in d, so that a hang shows where everyone waits, and fails it with what f
// returns. f does not touch t: it may still run after the test is over.
func within(t *testing.T, d time.Duration, what string, f func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("%s: %v", what, err)
		}
	case <-time.After(d):
		t.Fatalf("%s hangs after %v:\n%s", what, d, allStacks())
	}
}

func allStacks() string {
	buf := make([]byte, 1<<22)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// goroutines returns the stacks of all goroutines by their IDs, which the
// runtime never reuses.
func goroutines() map[string]string {
	stacks := map[string]string{}
	for _, g := range strings.Split(allStacks(), "\n\n") {
		id, _, _ := strings.Cut(strings.TrimPrefix(g, "goroutine "), " ")
		stacks[id] = g
	}
	return stacks
}

// goroutinesSettle fails the test with their stacks unless the goroutines
// started since before that run this package's code or HTTP/2 all end. Those
// of earlier tests that are still winding down, and the runtime's own, are not
// the test's and do not count.
func goroutinesSettle(t *testing.T, before map[string]string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var left []string
		for id, g := range goroutines() {
			if _, ok := before[id]; !ok && (strings.Contains(g, "/splithttp.") || strings.Contains(g, "http2")) {
				left = append(left, g)
			}
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines outlive the connection:\n\n%s", len(left), strings.Join(left, "\n\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitWriteStuck returns once a write holds c's write lock, as it does while
// it waits in the socket.
func waitWriteStuck(t *testing.T, c *flowConn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.wmu.TryLock() {
		c.wmu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("no write took the write lock")
		}
		time.Sleep(time.Millisecond)
	}
}

// A Read or Write that waits on the socket returns once the connection is
// closed, on either side and whoever holds the write lock, and a Read never
// waits for a Write: the read loop of the stack keeps going while its writes
// are stuck. Nothing the governor started outlives the connection.
func TestFlowCloseUnblocksReadAndWrite(t *testing.T) {
	var settings, ping, data bytes.Buffer
	fr := http2.NewFramer(&settings, nil)
	fr.WriteSettings()
	fr = http2.NewFramer(&ping, nil)
	fr.WritePing(false, [8]byte{1})
	fr = http2.NewFramer(&data, nil)
	fr.WriteData(1, false, make([]byte, 1000))
	read := func(c *flowConn, b []byte) error {
		_, err := c.Read(b)
		return err
	}
	// server returns a server-side governor past the client preface.
	server := func(t *testing.T, sc *stallConn) *flowConn {
		c := newFlowConn(sc, flowDefault, flowDefault)
		sc.in <- []byte(h2Preface)
		if err := read(c, make([]byte, 64)); err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, sc *stallConn) (*flowConn, []func() error)
	}{
		{"server read", func(t *testing.T, sc *stallConn) (*flowConn, []func() error) {
			c := newFlowConn(sc, flowDefault, flowDefault)
			return c, []func() error{func() error { return read(c, make([]byte, 64)) }}
		}},
		{"client read", func(t *testing.T, sc *stallConn) (*flowConn, []func() error) {
			c := newFlowClientConn(sc)
			return c, []func() error{func() error { return read(c, make([]byte, 64)) }}
		}},
		{"server write", func(t *testing.T, sc *stallConn) (*flowConn, []func() error) {
			c := server(t, sc)
			sc.stalled.Store(true)
			w := make(chan error, 1)
			go func() {
				_, err := c.Write(settings.Bytes())
				w <- err
			}()
			// The write holds wmu inside the socket; the read side and an
			// injection still go through.
			waitWriteStuck(t, c)
			within(t, 5*time.Second, "read beside a stuck write", func() error {
				sc.in <- settings.Bytes()
				err := read(c, make([]byte, 64))
				c.injectToClient(ping.Bytes())
				return err
			})
			return c, []func() error{func() error { return <-w }}
		}},
		{"client write", func(t *testing.T, sc *stallConn) (*flowConn, []func() error) {
			c := newFlowClientConn(sc)
			sc.stalled.Store(true)
			w := make(chan error, 1)
			go func() {
				_, err := c.Write(append([]byte(h2Preface), settings.Bytes()...))
				w <- err
			}()
			waitWriteStuck(t, c)
			within(t, 5*time.Second, "read beside a stuck write", func() error {
				sc.in <- settings.Bytes()
				return read(c, make([]byte, 64))
			})
			return c, []func() error{func() error { return <-w }}
		}},
		{"queue flush", func(t *testing.T, sc *stallConn) (*flowConn, []func() error) {
			c := server(t, sc)
			if _, err := c.Write(settings.Bytes()); err != nil {
				t.Fatal(err)
			}
			sc.stalled.Store(true)
			// The flush goroutine takes wmu and waits in the socket, then
			// the stack's own write waits for wmu.
			c.injectToClient(ping.Bytes())
			if c.wmu.TryLock() {
				t.Fatal("no flush in progress")
			}
			w := make(chan error, 1)
			go func() {
				_, err := c.Write(data.Bytes())
				w <- err
			}()
			return c, []func() error{func() error { return <-w }}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := goroutines()
			sc := newStallConn()
			c, waits := tc.run(t, sc)
			errs := make(chan error, len(waits))
			for _, wait := range waits {
				go func() { errs <- wait() }()
			}
			time.Sleep(20 * time.Millisecond)
			within(t, 5*time.Second, "Close", func() error {
				c.Close()
				for range waits {
					if err := <-errs; err == nil {
						return errors.New("a call on a closed connection succeeded")
					}
				}
				return nil
			})
			goroutinesSettle(t, before)
		})
	}
}

// When the client goes away while the server waits for its credit, with or
// without the guard probing it, the server's write fails at once, the governor
// drops the connection's state, and no goroutine stays behind.
func TestFlowPeerGoneWhileWaitingForCredit(t *testing.T) {
	for _, clientWindow := range []uint32{h2InitWindow, 4 << 20} {
		t.Run(fmt.Sprint(clientWindow), func(t *testing.T) {
			wrote := make(chan error, 1)
			tl, addr := startFlowServer(t, testUp, testDown, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				for {
					if _, err := w.Write(make([]byte, 64<<10)); err != nil {
						wrote <- err
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			before := goroutines()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			fr := http2.NewFramer(conn, conn)
			conn.Write([]byte(h2Preface))
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: clientWindow})
			fr.WriteWindowUpdate(0, 64<<20)
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: rawPostHeaders, EndHeaders: true})
			// Read what the server sends but never return credit, until it
			// stops for want of it and, with a window the client still owes
			// credit on, the guard probes it after its stock delay.
			go io.Copy(io.Discard, conn)
			deadline := time.Now().Add(10 * time.Second)
			for {
				var stuck, armed bool
				tl.each(func(c *flowConn) {
					if s := c.streams[1]; s != nil {
						stuck = s.downSent > 0 && int64(c.clientShown)+s.downForwarded-s.downSent <= 0
					}
					armed = c.guardProbe
				})
				if stuck && (clientWindow == h2InitWindow || armed) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("server never ran out of credit (guard armed %v)", armed)
				}
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond)
			conn.Close()
			within(t, 5*time.Second, "server write after the client left", func() error {
				if err := <-wrote; err == nil {
					return errors.New("write succeeded")
				}
				return nil
			})
			goroutinesSettle(t, before)
			tl.each(func(c *flowConn) {
				if !c.closed || len(c.streams) > 0 || len(c.wqueue) > 0 {
					t.Errorf("state kept: closed %v, %d streams, %d bytes queued", c.closed, len(c.streams), len(c.wqueue))
				}
			})
		})
	}
}

// Connections closed at random points while both directions carry data on
// many streams neither hang a call nor leave goroutines behind.
func TestFlowCloseUnderLoad(t *testing.T) {
	tl, addr := startFlowServer(t, testUp, testDown, true, http.HandlerFunc(echoHandler))
	before := goroutines()
	for round := 0; round < 10; round++ {
		client := newFlowTestClient(t, addr, true)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest("POST", "http://x/", io.LimitReader(rand.Reader, 4<<20))
				resp, err := client.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()
		}
		time.Sleep(time.Duration(mrand.IntN(50)) * time.Millisecond)
		if round%2 == 0 {
			// Not tl.each: it holds c.mu, which Close takes too.
			tl.mu.Lock()
			conns := append([]*flowConn(nil), tl.conns...)
			tl.mu.Unlock()
			for _, c := range conns {
				c.Close()
			}
		} else {
			client.each(func(c *flowConn) { go c.Close() })
		}
		within(t, 10*time.Second, "requests on closed connections", func() error {
			wg.Wait()
			return nil
		})
		client.CloseIdleConnections()
	}
	goroutinesSettle(t, before)
}
