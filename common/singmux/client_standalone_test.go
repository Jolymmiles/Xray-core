package singmux

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
)

// R7. These cover the parts of the client-side leak fix (commit e7977eb6:
// client.go + retry_conn.go) that the T4/T6 suites leave untouched, and they do
// it without the server-side fix in the picture: nothing here constructs a
// Service, so the CLIENT commit carries its own proof and can ship ahead of, or
// without, the SERVER commit (befd4b39).
//
// Uncovered before this file: client.go 154-157 (sweeper interval fallback),
// 197-199 (sweep drops an already-closed carrier), 265-275 (openStream evicts a
// carrier that cannot open a stream), retry_conn.go 72-74 (empty replay).

// soloCarrierConn completes the carrier handshake and then fails every write.
// That is the one way, from outside mplsmux, to make Session.OpenStream fail
// while Session.IsClosed() is still false: the frameOpen submit hits the failing
// write, and the session only reports closed afterwards. The other trigger --
// stream ID exhaustion -- sits behind an unexported counter.
//
// Read parks until Close so the session's read loop cannot tear the session down
// first, which would route the test through the pool's dead-session prune
// instead of the eviction path under test.
type soloCarrierConn struct {
	// carrierRequestBytes: writeCarrierRequest sends {version, protocol} in one
	// writeFull when padding is off, which is how these tests build the client.
	// Counting bytes rather than calls keeps the fake honest if that ever
	// becomes two writes.
	written atomic.Int64

	closeOnce  sync.Once
	closed     chan struct{}
	closeCalls atomic.Int32
}

const carrierRequestBytes = 2

func newSoloCarrierConn() *soloCarrierConn {
	return &soloCarrierConn{closed: make(chan struct{})}
}

func (c *soloCarrierConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *soloCarrierConn) Write(payload []byte) (int, error) {
	if c.written.Add(int64(len(payload))) <= carrierRequestBytes {
		return len(payload), nil
	}
	return 0, errors.New("carrier write failed")
}

func (c *soloCarrierConn) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *soloCarrierConn) LocalAddr() net.Addr              { return nil }
func (c *soloCarrierConn) RemoteAddr() net.Addr             { return nil }
func (c *soloCarrierConn) SetDeadline(time.Time) error      { return nil }
func (c *soloCarrierConn) SetReadDeadline(time.Time) error  { return nil }
func (c *soloCarrierConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*soloCarrierConn)(nil)

// soloCarrierDialer hands out exactly one unusable carrier and then refuses, so
// openStream's retry loop terminates on the dial error instead of spinning up
// fresh carriers for the rest of the test.
type soloCarrierDialer struct {
	carrier *soloCarrierConn
	dials   atomic.Int32
}

func (d *soloCarrierDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	if d.dials.Add(1) == 1 {
		return d.carrier, nil
	}
	return nil, errors.New("no more carriers")
}

// soloDeadlineConn records the deadline and write traffic a replay puts on a
// replacement stream.
type soloDeadlineConn struct {
	deadlineCalls atomic.Int32
	writeCalls    atomic.Int32
}

func (c *soloDeadlineConn) Read([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *soloDeadlineConn) Close() error                    { return nil }
func (c *soloDeadlineConn) LocalAddr() net.Addr             { return nil }
func (c *soloDeadlineConn) RemoteAddr() net.Addr            { return nil }
func (c *soloDeadlineConn) SetDeadline(time.Time) error     { return nil }
func (c *soloDeadlineConn) SetReadDeadline(time.Time) error { return nil }

func (c *soloDeadlineConn) Write(payload []byte) (int, error) {
	c.writeCalls.Add(1)
	return len(payload), nil
}

func (c *soloDeadlineConn) SetWriteDeadline(time.Time) error {
	c.deadlineCalls.Add(1)
	return nil
}

var _ net.Conn = (*soloDeadlineConn)(nil)

// vacatedTailIsCleared reports whether the pool's backing array holds a stale
// *pooledSession past the live length. A stale entry there pins the evicted
// carrier's session, its two loop goroutines and its conn for as long as the
// array lives -- S2 L2.
func (c *Client) vacatedTailIsCleared() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pooled := range c.sessions[len(c.sessions):cap(c.sessions)] {
		if pooled != nil {
			return false
		}
	}
	return true
}

// A Client that was not built by NewClient has a zero sweepInterval. Without
// the fallback that reaches time.NewTicker(0), which panics and takes the whole
// process down -- so the assertion here is the run itself: a regression cannot
// reach the end of this test, because the panic happens on the sweeper
// goroutine where no recover() is in scope.
func TestClientSweeperFallsBackWhenIntervalUnset(t *testing.T) {
	client := &Client{}
	t.Cleanup(func() { _ = client.Close() })

	client.mu.Lock()
	client.startSweeperLocked()
	sweeper := client.sweeper
	client.mu.Unlock()

	if sweeper == nil {
		t.Fatal("startSweeperLocked left c.sweeper nil; a pooled carrier would never be reaped")
	}
	// Let the goroutine reach time.NewTicker before the test returns.
	time.Sleep(20 * time.Millisecond)
}

// A carrier that is already closed must leave the pool on the first sweep, and
// must not be handed back for another Close.
//
// The live carrier in the same sweep is the control: it is idle by exactly the
// same measure (no streams, nothing handed out since the last sweep) and it
// survives, because the two-sweep confirmation still applies to it. The only
// difference between the two entries is IsClosed(), so the drop is causal.
func TestClientSweepDropsClosedCarrierWithoutReclosing(t *testing.T) {
	dialer := &blackholeDialer{}
	client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Only the explicit sweepIdle call below may sweep; an interval short enough
	// to fire on its own would make the assertions racy.
	client.sweepInterval = time.Hour
	t.Cleanup(func() { _ = client.Close() })

	// MaxStreams 1 forces the second stream onto a second carrier.
	for _, stream := range openStreams(t, client, 2) {
		_ = stream.Close()
	}
	if got := client.pooledSessions(); got != 2 {
		t.Fatalf("pooled carriers = %d, want 2 (the sweep needs a closed one and a live control)", got)
	}

	client.mu.Lock()
	closedCarrier := client.sessions[0].session
	liveCarrier := client.sessions[1].session
	sweeper := client.sweeper
	client.mu.Unlock()
	if err := closedCarrier.Close(); err != nil {
		t.Fatal(err)
	}

	expired, drained := client.sweepIdle(sweeper)

	if len(expired) != 0 {
		t.Fatalf("sweep returned %d carriers to close, want 0 (an already-closed carrier must not be closed again)", len(expired))
	}
	if drained {
		t.Fatal("sweep retired itself while a live carrier was still pooled")
	}
	if got := client.pooledSessions(); got != 1 {
		t.Fatalf("pooled carriers after the sweep = %d, want 1 (closed carrier dropped, live one kept)", got)
	}
	client.mu.Lock()
	survivor := client.sessions[0].session
	client.mu.Unlock()
	if survivor != liveCarrier {
		t.Fatal("the sweep kept the closed carrier and dropped the live one")
	}
	if !client.vacatedTailIsCleared() {
		t.Fatal("the dropped carrier is still pinned by the pool's backing array")
	}
}

// A carrier that dials and handshakes but cannot open a stream must be dropped
// from the pool, and dropping it must clear the slot it vacated.
//
// What this pins, by mutation: rewriting the eviction as the pre-fix
// `c.sessions = append(c.sessions[:index], c.sessions[index+1:]...)` fails here,
// because that form leaves the evicted *pooledSession live in the backing array
// -- S2 L2. The eviction's own `selected.session.Close()` is NOT pinned: on this
// path mplsmux fail() has already closed the carrier conn, so removing that line
// still passes. It is defence for an OpenStream failure that leaves the session
// alive (stream ID exhaustion), which is unreachable from this package.
func TestClientEvictsCarrierThatCannotOpenStream(t *testing.T) {
	carrier := newSoloCarrierConn()
	dialer := &soloCarrierDialer{carrier: carrier}
	client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxStreams: 2})
	if err != nil {
		t.Fatal(err)
	}
	client.sweepInterval = time.Hour // eviction, not the sweeper, must do the work
	t.Cleanup(func() { _ = client.Close() })

	stream, err := client.openStream(context.Background())
	if err == nil {
		_ = stream.Close()
		t.Fatal("openStream succeeded on a carrier whose writes always fail")
	}
	if got := dialer.dials.Load(); got != 2 {
		t.Fatalf("carrier dials = %d, want 2 (evict the broken carrier, then fail on the redial)", got)
	}
	if got := carrier.closeCalls.Load(); got == 0 {
		t.Fatal("the carrier conn was still open after its session was evicted")
	}
	if got := client.pooledSessions(); got != 0 {
		t.Fatalf("pooled carriers after eviction = %d, want 0", got)
	}
	if !client.vacatedTailIsCleared() {
		t.Fatal("the evicted carrier is still pinned by the pool's backing array")
	}
}

// An empty replay must not touch the replacement's write deadline. replayTo
// stamps a bounded deadline and then clears it with the zero time; doing that
// for a replacement with nothing to replay costs two syscalls on the retry path
// and clears whatever deadline the caller had already set on that conn.
func TestRetryConnReplayToSkipsEmptyReplay(t *testing.T) {
	replacement := &soloDeadlineConn{}
	connection := newRetryConn(context.Background(), replacement, unavailableOpener)
	t.Cleanup(func() { _ = connection.Close() })

	if err := connection.replayTo(replacement, nil); err != nil {
		t.Fatalf("replayTo with an empty replay = %v, want nil", err)
	}
	if got := replacement.deadlineCalls.Load(); got != 0 {
		t.Fatalf("SetWriteDeadline calls for an empty replay = %d, want 0", got)
	}
	if got := replacement.writeCalls.Load(); got != 0 {
		t.Fatalf("Write calls for an empty replay = %d, want 0", got)
	}
}

// The reader parked in awaitResponse waits on three things: a replacement, the
// close signal the fix added, and its context. The close signal has its own
// test; this one holds the context arm, so a regression that collapses the
// select cannot leave a cancelled dispatch parked on a carrier that will never
// produce a replacement.
func TestRetryConnAwaitResponseUnblocksOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initial := newGatedConn()
	connection := newRetryConn(ctx, initial, unavailableOpener)
	t.Cleanup(func() { _ = connection.Close() })

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_, _ = connection.Write([]byte("request"))
	}()
	<-initial.writeEntered

	readDone := make(chan error, 1)
	go func() {
		destination := make([]byte, 4)
		_, err := connection.Read(destination)
		readDone <- err
	}()

	// Same shape as TestRetryConnReadUnblocksOnClose: fail the response read so
	// awaitResponse takes the retry path, then give the reader time to reach the
	// select. Cancelling before it parks would unwind it through c.current()
	// instead, and the arm under test would never run.
	initial.readGate <- errors.New("carrier read failed")
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case err := <-readDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Read error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read remained parked in awaitResponse after its context was cancelled")
	}

	_ = connection.Close()
	<-writeDone
}
