// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/transport"
)

// backlogStreams fills the session accept backlog exactly (mplsmux caps it at
// 512), which is the load teardown has to survive.
const backlogStreams = 512

// blockedWriteConn models the carrier state that makes teardown expensive: the
// peer has stopped reading, so every carrier write parks until the connection
// is closed and then fails. A stalled TCP socket behaves this way, and it is
// the only state in which mplsmux's 30s closeTimeout is actually reached.
type blockedWriteConn struct {
	net.Conn
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *blockedWriteConn) Write([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockedWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// newBacklogCarrier returns a server session holding backlogStreams
// queued-but-unaccepted streams, each carrying payload, over a stalled carrier.
//
// The session is built directly rather than through NewConnection on purpose:
// the accept loop drains the backlog as fast as the peer fills it, so driving
// this end to end could not put a known number of streams in the queue.
func newBacklogCarrier(t *testing.T, payload []byte) *localsmux.Session {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	stalled := &blockedWriteConn{Conn: serverRaw, closed: make(chan struct{})}

	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	serverSession, err := localsmux.Server(stalled, config)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := localsmux.DefaultConfig()
	clientConfig.KeepAliveDisabled = true
	clientSession, err := localsmux.Client(clientRaw, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = clientRaw.Close()
		_ = stalled.Close()
	})

	for range backlogStreams {
		stream, err := clientSession.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	// The streams are registered by the server read loop, not by the client, so
	// wait for them rather than assuming they have landed.
	deadline := time.Now().Add(10 * time.Second)
	for serverSession.NumStreams() < backlogStreams {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d streams reached the server backlog", serverSession.NumStreams(), backlogStreams)
		}
		time.Sleep(time.Millisecond)
	}
	return serverSession
}

// Teardown must not walk the accept backlog closing streams one at a time.
// mplsmux bounds Stream.Close only by its 30s closeTimeout, and the close is
// serialised behind submitMu, so on a stalled carrier the very first queued
// stream held teardown for the full 30s — measured at 30.0026s against the
// previous drainAcceptBacklog — while the carrier, its session goroutines and
// every handler stayed pinned. Worse, the drain then gave up: its own 10ms
// accept deadline had expired 30 seconds earlier, so the remaining 511 streams
// were abandoned unclosed and the pass bought nothing at all.
func TestServiceTeardownWithFullAcceptBacklogIsBounded(t *testing.T) {
	service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
	service.handlerDrainTimeout = 100 * time.Millisecond

	payload := []byte("queued")
	session := newBacklogCarrier(t, payload)
	// Hold two of the queued streams so the reclaim below is observable.
	// Accepting only hands over a reference; they stay registered either way.
	held := make([]*localsmux.Stream, 0, 2)
	for range cap(held) {
		stream, err := session.AcceptStream()
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, stream)
	}
	if streams := session.NumStreams(); streams != backlogStreams {
		t.Fatalf("backlog holds %d streams, want %d: teardown would not be exercised", streams, backlogStreams)
	}

	_, cancelHandlers := context.WithCancel(context.Background())
	var handlers handlerGroup

	elapsed := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		service.tearDown(session, cancelHandlers, &handlers)
		elapsed <- time.Since(start)
	}()
	select {
	case took := <-elapsed:
		if took > time.Second {
			t.Fatalf("teardown of a %d-stream backlog took %v, want under 1s", backlogStreams, took)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("teardown of a %d-stream backlog did not finish within 60s", backlogStreams)
	}

	if !session.IsClosed() {
		t.Fatal("teardown returned without closing the session: fail() never ran, so nothing reclaimed the backlog")
	}
	// This is the reclaim assertion. Stream.Read serves buffered chunks before
	// it reports any closed state, so a read that returns data here would mean
	// the queued receive buffers — and the slice of the session-wide reservation
	// they hold — survived teardown. The byte-level proof lives where the
	// counter does, in mplsmux's own session/stream leak tests.
	for index, stream := range held {
		destination := make([]byte, len(payload))
		if n, err := stream.Read(destination); err == nil {
			t.Fatalf("held stream %d still returned %d queued bytes after teardown: receive buffers leaked", index, n)
		}
	}
}

// stalledHandlerDispatcher never returns, whatever happens to its context or
// its stream. It is the only case in which the handler drain bound is reached.
type stalledHandlerDispatcher struct {
	detachedDispatcher
	entered chan struct{}
	release chan struct{}
}

func (d *stalledHandlerDispatcher) DispatchLink(context.Context, X.Destination, *transport.Link) error {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	<-d.release
	return nil
}

// Bounding the handler drain must not cost a goroutine of its own. A carrier
// whose dispatcher never returns already strands that handler; parking a second
// goroutine on sync.WaitGroup.Wait just to time it out doubles the residue, and
// it accumulates once per stalled carrier.
func TestServiceTeardownLeavesNoWaiterGoroutine(t *testing.T) {
	const carriers = 8
	release := make(chan struct{})
	defer close(release)

	baseline := settledGoroutines()
	for range carriers {
		dispatcher := &stalledHandlerDispatcher{
			detachedDispatcher: detachedDispatcher{started: make(chan struct{}, 1)},
			entered:            make(chan struct{}, 1),
			release:            release,
		}
		service := NewService(dispatcher)
		service.streamHandshakeTimeout = time.Second
		service.handlerDrainTimeout = 50 * time.Millisecond

		clientConn, serverConn := newCNCCarrierPair()
		session, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)
		openDispatchedStream(t, session, dispatcher.entered)
		_ = clientConn.Close()
		if _, returned := awaitCarrierResult(result, 5*time.Second); !returned {
			t.Fatal("NewConnection did not return after the drain bound expired")
		}
	}

	// One stranded handler per carrier is irreducible: a dispatcher that
	// observes neither its context nor its stream cannot be stopped from
	// outside. Anything beyond that is the service's own residue, and there must
	// be none — the previous waiter goroutine put the count at 2 per carrier.
	leaked := settledGoroutines() - baseline
	t.Logf("residue after %d stalled carriers: %d goroutines", carriers, leaked)
	if leaked > carriers+2 {
		t.Fatalf("goroutine count grew by %d over %d stalled carriers, want at most %d: teardown strands a waiter of its own", leaked, carriers, carriers+2)
	}
}

// Control for the bound above: the same carriers with a dispatcher that does
// return must leave nothing at all behind. Without this, the assertion could
// pass simply because the handlers were never stalled.
func TestServiceTeardownLeavesNothingForWellBehavedHandlers(t *testing.T) {
	const carriers = 8
	baseline := settledGoroutines()
	for range carriers {
		dispatcher := &detachedDispatcher{started: make(chan struct{}, 1)}
		service := NewService(dispatcher)
		service.streamHandshakeTimeout = time.Second
		service.handlerDrainTimeout = 5 * time.Second

		clientConn, serverConn := newCNCCarrierPair()
		session, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)
		openDispatchedStream(t, session, dispatcher.started)
		_ = clientConn.Close()
		if _, returned := awaitCarrierResult(result, 5*time.Second); !returned {
			t.Fatal("NewConnection did not return after the carrier died")
		}
	}
	leaked := settledGoroutines() - baseline
	t.Logf("residue after %d well-behaved carriers: %d goroutines", carriers, leaked)
	if leaked > 2 {
		t.Fatalf("goroutine count grew by %d over %d well-behaved carriers", leaked, carriers)
	}
}

// handlerGroup's drain must be safe to ask for more than once and must not
// close its channel twice when the last handler leaves concurrently.
func TestHandlerGroupDrainIsIdempotent(t *testing.T) {
	var group handlerGroup
	if _, open := <-group.drain(); open {
		t.Fatal("an empty group did not report itself drained")
	}
	<-group.drain()

	var busy handlerGroup
	busy.add()
	drained := busy.drain()
	select {
	case <-drained:
		t.Fatal("a group with a live handler reported itself drained")
	default:
	}
	busy.done()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("the last handler leaving did not close the drain channel")
	}
	<-busy.drain()
}
