package singmux

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
)

// testSweepInterval keeps the idle sweeper fast enough for tests while still
// exercising the two-sweep idle confirmation.
const testSweepInterval = 20 * time.Millisecond

// trackedConn counts carrier connections that are still open so tests can prove
// the client releases every carrier it dials.
type trackedConn struct {
	net.Conn
	live   *atomic.Int32
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.live.Add(-1)
	}
	return c.Conn.Close()
}

// trackingDialer hands out carriers backed by the in-process SMUX service and
// records how many of them are still open.
type trackingDialer struct {
	service *Service
	dials   atomic.Int32
	live    atomic.Int32
}

func (d *trackingDialer) DialContext(ctx context.Context, destination X.Destination) (net.Conn, error) {
	conn, err := (&serviceDialer{service: d.service}).DialContext(ctx, destination)
	if err != nil {
		return nil, err
	}
	d.dials.Add(1)
	d.live.Add(1)
	return &trackedConn{Conn: conn, live: &d.live}, nil
}

// blackholeDialer completes the carrier handshake and then goes permanently
// silent without ever closing: the D4 undetected-dead carrier. With keepalive
// disabled the session's readLoop parks in io.ReadFull forever, so IsClosed()
// stays false and the pool's dead-session prune can never see it.
type blackholeDialer struct {
	dials atomic.Int32
	live  atomic.Int32
}

func (d *blackholeDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	d.dials.Add(1)
	d.live.Add(1)
	go func() {
		defer serverConn.Close()
		if _, err := readCarrierRequest(serverConn); err != nil {
			return
		}
		// Consume whatever the client writes but never answer, so the carrier
		// looks alive to every liveness check the client still has.
		_, _ = io.Copy(io.Discard, serverConn)
	}()
	return &trackedConn{Conn: clientConn, live: &d.live}, nil
}

// failingDialer always refuses, exercising the carrier-handshake error paths.
type failingDialer struct{ dials atomic.Int32 }

func (d *failingDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	d.dials.Add(1)
	return nil, errors.New("dial refused")
}

// hangingDialer never answers the carrier handshake, so the client must fall
// back to context cancellation. The peer end is parked without a goroutine so
// the harness itself cannot pollute goroutine measurements.
type hangingDialer struct {
	live  atomic.Int32
	peers []net.Conn
}

func (d *hangingDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	d.live.Add(1)
	d.peers = append(d.peers, serverConn)
	return &trackedConn{Conn: clientConn, live: &d.live}, nil
}

func (d *hangingDialer) closePeers() {
	for _, peer := range d.peers {
		_ = peer.Close()
	}
	d.peers = nil
}

// newTestClient builds a client whose idle sweeper runs fast enough for tests.
// The interval is set before the first dial, which is what starts the sweeper,
// so no sweeper goroutine can observe the field mid-write.
func newTestClient(t *testing.T, options Options) *Client {
	t.Helper()
	options.Protocol = "smux"
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	client.sweepInterval = testSweepInterval
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// waitForCount polls until the counter settles at or below want. Polling avoids
// both fixed sleeps and the flakiness of a single post-cleanup sample.
func waitForCount(t *testing.T, actual *atomic.Int32, want int32) int32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	got := actual.Load()
	for time.Now().Before(deadline) {
		got = actual.Load()
		if got <= want {
			return got
		}
		time.Sleep(testSweepInterval / 2)
	}
	return got
}

func waitForGoroutines(t *testing.T, want int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	count := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		count = runtime.NumGoroutine()
		if count <= want {
			return count
		}
		time.Sleep(10 * time.Millisecond)
	}
	return count
}

// baselineGoroutines waits for goroutines left over from earlier tests to
// retire so the caller measures only its own scenario.
func baselineGoroutines(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	previous := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		current := runtime.NumGoroutine()
		if current >= previous {
			return current
		}
		previous = current
	}
	return previous
}

func (c *Client) pooledSessions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sessions)
}

func openStreams(t *testing.T, client *Client, count int) []net.Conn {
	t.Helper()
	streams := make([]net.Conn, 0, count)
	for range count {
		stream, err := client.openStream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, stream)
	}
	return streams
}

// A burst of streams grows the carrier pool. Once every stream is closed the
// pool must release the carriers instead of pinning them, along with the SMUX
// session goroutines each carrier keeps alive.
func TestClientReapsIdleCarriers(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 64)}
	dialer := &trackingDialer{service: NewService(dispatcher)}
	client := newTestClient(t, Options{Dialer: dialer, MaxStreams: 2})

	streams := openStreams(t, client, 32)
	peak := dialer.live.Load()
	if peak < 2 {
		t.Fatalf("live carriers during burst = %d, want the pool to grow past one", peak)
	}
	// R2 gate (D10): prove the sweeper is actually running, so a later "0 live
	// carriers" cannot pass vacuously via a reaper that never started.
	client.mu.Lock()
	sweeping := client.sweeper != nil
	client.mu.Unlock()
	if !sweeping {
		t.Fatal("no sweeper started after the first carrier was dialed")
	}
	for _, stream := range streams {
		_ = stream.Close()
	}

	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("live carriers after idle sweep = %d, want 0 (carrier leak)", got)
	}
	if got := client.pooledSessions(); got != 0 {
		t.Fatalf("pooled sessions after idle sweep = %d, want 0 (session-cache leak)", got)
	}
}

// The leak reaches production through Dispatch: proxied connections grow the
// pool and finish, and the carriers must not stay pinned afterwards. This
// asserts the pool drains on its own, without a Close to do the work.
func TestClientReapsCarriersAfterDispatch(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 64)}
	dialer := &trackingDialer{service: NewService(dispatcher)}
	client := newTestClient(t, Options{Dialer: dialer, MaxStreams: 2})

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	var dispatches sync.WaitGroup
	for range 8 {
		dispatches.Go(func() {
			clientLink, _ := linkPair()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_ = client.Dispatch(ctx, clientLink, destination)
		})
	}
	dispatches.Wait()

	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("live carriers after dispatches finished = %d, want 0 (carrier leak)", got)
	}
	if got := client.pooledSessions(); got != 0 {
		t.Fatalf("pooled sessions after dispatches finished = %d, want 0 (session-cache leak)", got)
	}
}

// D4: a carrier whose peer went silent without closing is never detected as
// dead, because KeepAliveDisabled removes the only liveness check and the
// pool's prune only drops sessions that already report IsClosed(). The idle
// sweeper must retire it anyway once it stops carrying streams.
func TestClientReapsUndetectedDeadCarrier(t *testing.T) {
	// Control (D10 anti-vacuous-pass gate): with a sweep interval that cannot
	// fire during the test, the very same carrier stays pinned. That is what
	// makes the reaping assertion below causal rather than a carrier count
	// that happened to reach zero on its own.
	t.Run("pinned when the sweeper cannot fire", func(t *testing.T) {
		dialer := &blackholeDialer{}
		client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxStreams: 2})
		if err != nil {
			t.Fatal(err)
		}
		client.sweepInterval = time.Hour
		t.Cleanup(func() { _ = client.Close() })

		streams := openStreams(t, client, 1)
		for _, stream := range streams {
			_ = stream.Close()
		}
		// Same wall-clock budget the reaping case below gets to succeed in.
		time.Sleep(6 * testSweepInterval)

		if got := dialer.live.Load(); got != 1 {
			t.Fatalf("live carriers without a sweep = %d, want 1 (the pool drops carriers on its own, so the reaping test proves nothing)", got)
		}
		if got := client.pooledSessions(); got != 1 {
			t.Fatalf("pooled sessions without a sweep = %d, want 1", got)
		}
	})

	dialer := &blackholeDialer{}
	client := newTestClient(t, Options{Dialer: dialer, MaxStreams: 2})

	streams := openStreams(t, client, 1)
	client.mu.Lock()
	pooled := client.sessions[0]
	client.mu.Unlock()
	// The whole point of D4: the session still looks perfectly healthy.
	if pooled.session.IsClosed() {
		t.Fatal("carrier reported closed; this test must cover the undetected-dead case")
	}
	for _, stream := range streams {
		_ = stream.Close()
	}

	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("live carriers after idle sweep = %d, want 0 (undetected-dead carrier pinned)", got)
	}
	if got := client.pooledSessions(); got != 0 {
		t.Fatalf("pooled sessions after idle sweep = %d, want 0", got)
	}
	// D5 cascade, first link: reaping must Close the session, which closes the
	// carrier conn. The outbound Process goroutine downstream unwinds from that
	// conn close via cnc.ConnectionOnClose in singmux_dialer.go.
	if !pooled.session.IsClosed() {
		t.Fatal("reaped session was dropped from the pool without being closed")
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("carrier dials = %d, want exactly 1 reaped carrier", got)
	}
}

// Reaping must not tear down a carrier that is still serving a stream.
func TestClientKeepsBusyCarriers(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 8)}
	dialer := &trackingDialer{service: NewService(dispatcher)}
	client := newTestClient(t, Options{Dialer: dialer, MaxStreams: 2})

	streams := openStreams(t, client, 1)
	// Span several sweeps so an over-eager reaper would have fired by now.
	time.Sleep(6 * testSweepInterval)

	if got := dialer.live.Load(); got != 1 {
		t.Fatalf("live carriers with an open stream = %d, want 1", got)
	}
	if got := client.pooledSessions(); got != 1 {
		t.Fatalf("pooled sessions with an open stream = %d, want 1", got)
	}
	if _, err := streams[0].Write([]byte("ping")); err != nil {
		t.Fatalf("write on a surviving carrier failed: %v", err)
	}
	_ = streams[0].Close()
	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("live carriers after the stream closed = %d, want 0", got)
	}
}

// Once the pool drains, the sweeper itself must retire rather than ticking for
// the lifetime of the process, and a later stream must start a fresh sweeper.
func TestClientSweeperRetiresWithEmptyPoolAndRestarts(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 8)}
	dialer := &trackingDialer{service: NewService(dispatcher)}
	client := newTestClient(t, Options{Dialer: dialer, MaxStreams: 2})
	baseline := baselineGoroutines(t)

	streams := openStreams(t, client, 1)
	for _, stream := range streams {
		_ = stream.Close()
	}
	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("live carriers after idle sweep = %d, want 0", got)
	}
	if got := waitForGoroutines(t, baseline); got > baseline {
		t.Fatalf("goroutines after the pool drained = %d, want <= %d (sweeper still running)", got, baseline)
	}

	// The pool must still be usable after its sweeper retired.
	revived := openStreams(t, client, 1)
	if got := dialer.live.Load(); got != 1 {
		t.Fatalf("live carriers after revival = %d, want 1", got)
	}
	for _, stream := range revived {
		_ = stream.Close()
	}
	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("revived carrier was not reaped, live = %d, want 0", got)
	}
}

// Session.Close blocks on loops.Wait, so a reaper that closed a carrier while
// holding c.mu would park every concurrent openStream on the pool mutex. Sweeps
// fire continuously here while openStream hammers the pool; a regression
// deadlocks instead of failing, which the -count flake gate surfaces as a
// timeout.
func TestClientSweepDoesNotBlockOpenStream(t *testing.T) {
	dialer := &blackholeDialer{}
	client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Sweep far faster than the workers, so reaping and opening interleave.
	client.sweepInterval = time.Millisecond
	t.Cleanup(func() { _ = client.Close() })

	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 40 {
				stream, err := client.openStream(context.Background())
				if err != nil {
					// A carrier reaped mid-open is expected here; the contract
					// under test is that the call returns at all.
					continue
				}
				_ = stream.Close()
			}
		})
	}

	finished := make(chan struct{})
	go func() {
		workers.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("openStream deadlocked against the idle sweeper (carrier closed while holding c.mu?)")
	}
}

// Close must release every pooled carrier and leave no client goroutine behind.
func TestClientCloseReleasesPoolAndGoroutines(t *testing.T) {
	baseline := baselineGoroutines(t)
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 64)}
	dialer := &trackingDialer{service: NewService(dispatcher)}
	client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxStreams: 2})
	if err != nil {
		t.Fatal(err)
	}
	// Keep the production sweep interval so Close, not the sweeper, does the work.
	streams := openStreams(t, client, 16)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for _, stream := range streams {
		_ = stream.Close()
	}

	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("live carriers after Close = %d, want 0", got)
	}
	if got := client.pooledSessions(); got != 0 {
		t.Fatalf("pooled sessions after Close = %d, want 0", got)
	}
	if got := waitForGoroutines(t, baseline); got > baseline {
		t.Fatalf("goroutines after Close = %d, want <= %d", got, baseline)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

// Refused carrier dials must not accumulate goroutines or pooled sessions.
func TestClientFailedDialsAreLeakFree(t *testing.T) {
	baseline := baselineGoroutines(t)
	dialer := &failingDialer{}
	client := newTestClient(t, Options{Dialer: dialer})

	for range 50 {
		if _, err := client.openStream(context.Background()); err == nil {
			t.Fatal("dial failure must surface to the caller")
		}
	}
	if got := client.pooledSessions(); got != 0 {
		t.Fatalf("pooled sessions after failed dials = %d, want 0", got)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if got := waitForGoroutines(t, baseline); got > baseline {
		t.Fatalf("goroutines after failed dials = %d, want <= %d", got, baseline)
	}
}

// A carrier handshake cancelled by context must close its carrier and stop its
// watcher goroutine.
func TestClientCancelledHandshakeIsLeakFree(t *testing.T) {
	baseline := baselineGoroutines(t)
	dialer := &hangingDialer{}
	t.Cleanup(dialer.closePeers)
	client := newTestClient(t, Options{Dialer: dialer})

	for range 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := client.openStream(ctx)
		cancel()
		if err == nil {
			t.Fatal("cancelled handshake must fail")
		}
	}
	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("live carriers after cancelled handshakes = %d, want 0", got)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if got := waitForGoroutines(t, baseline); got > baseline {
		t.Fatalf("goroutines after cancelled handshakes = %d, want <= %d", got, baseline)
	}
}

// Dispatch runs two copy goroutines per call; both must retire once the
// context is cancelled, otherwise every proxied connection leaks a goroutine.
func TestClientDispatchIsGoroutineLeakFree(t *testing.T) {
	baseline := baselineGoroutines(t)
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 16)}
	dialer := &trackingDialer{service: NewService(dispatcher)}
	client := newTestClient(t, Options{Dialer: dialer, MaxConnections: 1})

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	for range 8 {
		clientLink, _ := linkPair()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_ = client.Dispatch(ctx, clientLink, destination)
		cancel()
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if got := waitForCount(t, &dialer.live, 0); got != 0 {
		t.Fatalf("live carriers after dispatch = %d, want 0", got)
	}
	if got := waitForGoroutines(t, baseline); got > baseline {
		t.Fatalf("goroutines after dispatch = %d, want <= %d", got, baseline)
	}
}
