package splithttp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	gotls "crypto/tls"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// flowClient is an XHTTP-like HTTP/2 client: x/net's transport over a dialed
// connection, optionally governed, keeping the governed connections around.
type flowClient struct {
	*http.Client
	mu    sync.Mutex
	conns []*flowConn
}

func newFlowTestClient(addr string, governed bool) *flowClient {
	fc := &flowClient{}
	fc.Client = &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, _ string, _ *gotls.Config) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil || !governed {
				return c, err
			}
			g := newFlowClientConn(c)
			fc.mu.Lock()
			fc.conns = append(fc.conns, g)
			fc.mu.Unlock()
			return g, nil
		},
	}}
	return fc
}

func (fc *flowClient) each(f func(c *flowConn)) {
	fc.mu.Lock()
	conns := append([]*flowConn(nil), fc.conns...)
	fc.mu.Unlock()
	for _, c := range conns {
		c.mu.Lock()
		f(c)
		c.mu.Unlock()
	}
}

var clientCases = []struct {
	name     string
	up, down flowLimit
}{
	{"stock server", flowLimit{}, flowLimit{}},
	{"governed server", testUp, testDown},
}

func TestFlowClientSlowReaderBounded(t *testing.T) {
	for _, sc := range clientCases {
		for _, governed := range []bool{true, false} {
			var written atomic.Int64
			_, addr := startFlowServer(t, sc.up, sc.down, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf := make([]byte, 16<<10)
				for {
					n, err := w.Write(buf)
					written.Add(int64(n))
					if err != nil {
						return
					}
				}
			}))
			client := newFlowTestClient(addr, governed)
			resp, err := client.Get("http://x/down")
			if err != nil {
				t.Fatal(err)
			}
			var consumed atomic.Int64
			stop := make(chan struct{})
			go slowCopy(resp.Body, 256<<10, &consumed, stop)
			time.Sleep(3 * time.Second)
			var unread int64
			client.each(func(c *flowConn) {
				for _, s := range c.streams {
					unread = max(unread, s.downSent-s.down.returned)
				}
			})
			gap := written.Load() - consumed.Load()
			close(stop)
			resp.Body.Close()
			t.Logf("%s, governed client %v: server wrote %d, client read %d, gap %d, unread at client %d", sc.name, governed, written.Load(), consumed.Load(), gap, unread)
			if governed && unread > int64(h2InitWindow)+64<<10 {
				t.Fatalf("%s: unread at the governed client %d", sc.name, unread)
			}
			if governed && gap > 512<<10 {
				t.Fatalf("%s: gap %d between written and read", sc.name, gap)
			}
		}
	}
}

func TestFlowClientIntegrityDuplex(t *testing.T) {
	for _, sc := range clientCases {
		_, addr := startFlowServer(t, sc.up, sc.down, true, http.HandlerFunc(echoHandler))
		client := newFlowTestClient(addr, true)
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
			t.Fatalf("%s: %v", sc.name, err)
		}
	}
}

func clientDownloadRate(t *testing.T, sc struct {
	name     string
	up, down flowLimit
}, governed bool, rtt time.Duration,
) (float64, time.Duration) {
	const size = 64 << 20
	_, addr := startFlowServer(t, sc.up, sc.down, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32<<10)
		for sent := 0; sent < size; sent += len(buf) {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	client := newFlowTestClient(lagProxy(t, addr, rtt/2), governed)
	if resp, err := client.Get("http://x/warm"); err == nil {
		resp.Body.Read(make([]byte, 1))
		resp.Body.Close()
	}
	start := time.Now()
	resp, err := client.Get("http://x/down")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 32<<10)
	var got int
	var first4, half time.Time
	for {
		n, err := resp.Body.Read(buf)
		got += n
		if got >= 4<<20 && first4.IsZero() {
			first4 = time.Now()
		}
		if got >= size/2 && half.IsZero() {
			half = time.Now()
		}
		if err != nil {
			break
		}
	}
	if got != size {
		t.Fatalf("downloaded %d of %d", got, size)
	}
	return float64(size/2) / time.Since(half).Seconds() / (1 << 20), first4.Sub(start)
}

func TestFlowClientKeepsThroughput(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing-sensitive")
	}
	rtt := 40 * time.Millisecond
	for _, sc := range clientCases {
		base, baseRamp := clientDownloadRate(t, sc, false, rtt)
		gov, govRamp := clientDownloadRate(t, sc, true, rtt)
		t.Logf("%s rtt=%v: steady stock client %.1f MiB/s, governed client %.1f MiB/s; first 4 MiB %v / %v",
			sc.name, rtt, base, gov, baseRamp.Round(time.Millisecond), govRamp.Round(time.Millisecond))
		if gov < base*0.85 {
			t.Fatalf("%s: governed client steady %.1f is below 85%% of %.1f", sc.name, gov, base)
		}
	}
}

func TestFlowClientMeasuresRTT(t *testing.T) {
	_, addr := startFlowServer(t, flowLimit{}, flowLimit{}, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 30; i++ {
			w.Write(make([]byte, 32<<10))
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	client := newFlowTestClient(lagProxy(t, addr, 25*time.Millisecond), true)
	resp, err := client.Get("http://x/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	var rtt time.Duration
	client.each(func(c *flowConn) { rtt = max(rtt, c.currentRTT()) })
	t.Logf("client measured rtt %v", rtt)
	if rtt < 40*time.Millisecond || rtt > 200*time.Millisecond {
		t.Fatalf("rtt %v is off the 50ms path", rtt)
	}
}

func TestFlowClientStreamStateReleased(t *testing.T) {
	for _, sc := range clientCases {
		_, addr := startFlowServer(t, sc.up, sc.down, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/hang":
				<-r.Context().Done()
			default:
				io.Copy(io.Discard, r.Body)
				w.Write(make([]byte, 100<<10))
			}
		}))
		client := newFlowTestClient(addr, true)
		var wg sync.WaitGroup
		for i := 0; i < 300; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1+mrand.IntN(100))*time.Millisecond)
				defer cancel()
				var req *http.Request
				switch i % 3 {
				case 0:
					req, _ = http.NewRequestWithContext(ctx, "POST", "http://x/ok", io.LimitReader(zeroReader{}, 64<<10))
				case 1:
					req, _ = http.NewRequestWithContext(ctx, "GET", "http://x/hang", nil)
				default:
					req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://x/ok", nil)
				}
				if resp, err := client.Do(req); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}(i)
		}
		wg.Wait()
		deadline := time.Now().Add(5 * time.Second)
		for {
			left := 0
			client.each(func(c *flowConn) {
				if !c.closed {
					left += len(c.streams)
				}
			})
			if left == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d stream states left on the client", sc.name, left)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// TestFlowChainedGovernorsSlowReaders puts a governor at both ends of twelve
// downloads, as on a bridge in front of a governed server, and reads them in
// stops and starts, so the caps shrink at both ends while each holds credit
// back. Every download must still complete: with the client showing more than
// the lowest cap (see flowShownDown) the two governors wait for each other.
func TestFlowChainedGovernorsSlowReaders(t *testing.T) {
	const size = 3 << 20
	_, addr := startFlowServer(t, testUp, testDown, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 16<<10)
		for left := size; left > 0; left -= len(buf) {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	client := newFlowTestClient(addr, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(ctx, "GET", "http://x/down", nil)
			resp, err := client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			buf := make([]byte, 8<<10)
			got := 0
			for {
				n, err := resp.Body.Read(buf)
				got += n
				if err == io.EOF {
					break
				}
				if err != nil {
					errs <- fmt.Errorf("after %d of %d bytes: %w", got, size, err)
					return
				}
				// Stop and start for the first two thirds, at random.
				if got < size*2/3 && mrand.IntN(8) == 0 {
					time.Sleep(time.Duration(mrand.IntN(60)) * time.Millisecond)
				}
			}
			if got != size {
				errs <- fmt.Errorf("read %d bytes, want %d", got, size)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
