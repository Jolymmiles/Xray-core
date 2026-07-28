// SPDX-License-Identifier: MPL-2.0

// This file deliberately carries no `integration` build tag even though it is
// named like the tagged suites in this package: it is the swarm's resource-leak
// regression gate, so it has to run in the default `go test -race ./common/singmux/`
// pass rather than behind an opt-in tag.

package singmux

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

const (
	// leakStreamCount is high enough that a per-stream leak is unmistakable in
	// the diff, and low enough to keep the gate cheap under -race.
	leakStreamCount = 8
	// leakSettleTimeout bounds the settle-poll. Teardown here is asynchronous —
	// closing a carrier unblocks copy loops and session loops out of band — so
	// the gate polls to a quiescent state instead of sleeping a fixed interval
	// and comparing once, which is either flaky or needlessly slow.
	leakSettleTimeout = 5 * time.Second
	leakSettleStep    = 25 * time.Millisecond
	// leakOwnerFrame matches both this package and its internal SMUX engine
	// (common/singmux/internal/mplsmux), including the trailing "created by"
	// frame. A goroutine parked entirely inside common/buf or transport/pipe is
	// still attributed here when SMUX started it.
	leakOwnerFrame = "common/singmux"
)

// leakGoroutines snapshots every live goroutine keyed by its runtime ID.
//
// The dump buffer grows until the profile fits: runtime.Stack truncates
// silently, and a truncated dump reads exactly like "nothing leaked". Stacks
// are large under -race, so a fixed-size buffer would quietly disarm the gate.
func leakGoroutines() map[string]string {
	for size := 1 << 20; ; size *= 2 {
		dump := make([]byte, size)
		written := runtime.Stack(dump, true)
		if written < size {
			return leakParseGoroutines(string(dump[:written]))
		}
	}
}

func leakParseGoroutines(dump string) map[string]string {
	records := make(map[string]string)
	for _, record := range strings.Split(dump, "\n\n") {
		record = strings.TrimSpace(record)
		header, _, found := strings.Cut(record, "\n")
		if !found || !strings.HasPrefix(header, "goroutine ") {
			continue
		}
		id, _, found := strings.Cut(strings.TrimPrefix(header, "goroutine "), " ")
		if !found || id == "" {
			continue
		}
		records[id] = record
	}
	return records
}

// leakOwnedGoroutines keeps only the goroutines SMUX is running or created.
func leakOwnedGoroutines() map[string]string {
	owned := make(map[string]string)
	for id, record := range leakGoroutines() {
		if strings.Contains(record, leakOwnerFrame) {
			owned[id] = record
		}
	}
	return owned
}

func leakNewGoroutines(baseline, current map[string]string) map[string]string {
	leaked := make(map[string]string)
	for id, record := range current {
		if _, existed := baseline[id]; !existed {
			leaked[id] = record
		}
	}
	return leaked
}

// leakAssertMeasuring fails when neither probe sees anything while the
// lifecycle is still live. A filter that silently selects zero goroutines, or a
// carrier set that is empty or already flagged closed, turns the whole gate
// into a no-op that always reports success — a worse outcome than a red build.
func leakAssertMeasuring(t *testing.T, baseline map[string]string, dialer *leakCarrierDialer, want int) {
	t.Helper()
	live := leakNewGoroutines(baseline, leakOwnedGoroutines())
	if len(live) < want {
		t.Fatalf("goroutine filter %q matched %d live goroutines mid-lifecycle, want at least %d: the leak gate is not measuring anything",
			leakOwnerFrame, len(live), want)
	}
	if open := dialer.openCarriers(); open == 0 {
		t.Fatal("no carrier ends were open mid-lifecycle: the carrier probe is not measuring anything")
	}
}

// leakAwaitSettled polls until teardown has reclaimed both goroutines and
// carriers, or the settle budget runs out.
func leakAwaitSettled(t *testing.T, baseline map[string]string, dialer *leakCarrierDialer) (map[string]string, int) {
	t.Helper()
	deadline := time.Now().Add(leakSettleTimeout)
	for {
		leaked := leakNewGoroutines(baseline, leakOwnedGoroutines())
		carriers := dialer.openCarriers()
		if len(leaked)+carriers == 0 || !time.Now().Before(deadline) {
			return leaked, carriers
		}
		time.Sleep(leakSettleStep)
	}
}

func leakReport(t *testing.T, scenario string, before, after int, leaked map[string]string, carriers int) {
	t.Helper()
	if len(leaked)+carriers == 0 {
		return
	}
	ids := make([]string, 0, len(leaked))
	for id := range leaked {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var report strings.Builder
	fmt.Fprintf(&report, "%s leaked %d goroutine(s) %v and %d unclosed carrier end(s) after teardown (runtime.NumGoroutine %d -> %d)",
		scenario, len(leaked), ids, carriers, before, after)
	for _, id := range ids {
		fmt.Fprintf(&report, "\n\n%s", leaked[id])
	}
	t.Fatal(report.String())
}

// leakCarrier records whether one end of a carrier was ever closed.
//
// A dead session that keeps hold of its carrier is a descriptor leak, and it is
// invisible to the goroutine diff. Counting process file descriptors would not
// see it either: these carriers are net.Pipe, which consumes no descriptor at
// all. Tracking the Close directly is both exact and portable, and it is the
// same signal — one pinned carrier conn per dead session.
type leakCarrier struct {
	net.Conn
	closed atomic.Bool
}

func (c *leakCarrier) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// leakCarrierDialer is a serviceDialer that keeps every carrier reachable so a
// scenario can drop it without a protocol shutdown.
type leakCarrierDialer struct {
	service *Service

	mu       sync.Mutex
	carriers []*leakCarrier
	refused  bool
}

func (d *leakCarrierDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	rawClient, rawServer := net.Pipe()
	clientConn := &leakCarrier{Conn: rawClient}
	serverConn := &leakCarrier{Conn: rawServer}
	d.mu.Lock()
	if d.refused {
		d.mu.Unlock()
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, net.ErrClosed
	}
	d.carriers = append(d.carriers, clientConn, serverConn)
	d.mu.Unlock()
	go func() { _ = d.service.NewConnection(context.Background(), serverConn) }()
	return clientConn, nil
}

// openCarriers counts carrier ends teardown has not closed.
func (d *leakCarrierDialer) openCarriers() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	open := 0
	for _, carrier := range d.carriers {
		if !carrier.closed.Load() {
			open++
		}
	}
	return open
}

// slam drops every carrier the way a dead TCP peer does and refuses further
// dials, so retryConn cannot quietly rebuild the session under teardown and
// hide the leak the scenario is measuring.
func (d *leakCarrierDialer) slam() {
	d.mu.Lock()
	d.refused = true
	carriers := append([]*leakCarrier(nil), d.carriers...)
	d.mu.Unlock()
	for _, carrier := range carriers {
		_ = carrier.Close()
	}
}

// leakStream is one logical SMUX stream driven through the public client API.
type leakStream struct {
	cancel context.CancelFunc
	peer   *transport.Link
	done   chan error
}

func leakOpenStreams(t *testing.T, client *Client, destination X.Destination) []*leakStream {
	t.Helper()
	streams := make([]*leakStream, 0, leakStreamCount)
	for range leakStreamCount {
		clientLink, peerLink := linkPair()
		ctx, cancel := context.WithCancel(context.Background())
		stream := &leakStream{cancel: cancel, peer: peerLink, done: make(chan error, 1)}
		go func() { stream.done <- client.Dispatch(ctx, clientLink, destination) }()
		streams = append(streams, stream)
	}
	return streams
}

func leakPayload(seed int) []byte {
	payload := make([]byte, 4096)
	for index := range payload {
		payload[index] = byte(index + seed)
	}
	return payload
}

// leakWrite pushes a payload without collecting the echo, leaving frames in
// flight on both directions of the carrier.
func leakWrite(t *testing.T, stream *leakStream, payload []byte) {
	t.Helper()
	// buf.FromBytes yields an unmanaged buffer, so the pipe releasing it does
	// not invalidate payload for a later comparison.
	if err := stream.peer.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
		t.Fatalf("write payload: %v", err)
	}
}

// leakEcho drives one full round trip. It reads inline rather than from a
// helper goroutine: a helper that hung would itself be attributed to this
// package and reported as a leak it caused.
func leakEcho(t *testing.T, stream *leakStream, payload []byte) {
	t.Helper()
	leakWrite(t, stream, payload)
	var echoed bytes.Buffer
	for echoed.Len() < len(payload) {
		buffers, err := stream.peer.Reader.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("read echo payload: %v", err)
		}
		for _, buffer := range buffers {
			_, _ = echoed.Write(buffer.Bytes())
		}
		buf.ReleaseMulti(buffers)
	}
	if !bytes.Equal(echoed.Bytes(), payload) {
		t.Fatalf("echo mismatch over %d bytes", len(payload))
	}
}

// leakAwaitDispatch waits for every Dispatch to return under one shared budget,
// and reports whether any of them stalled.
//
// The budget is shared rather than per-stream so a wedged session costs one
// settle window, not one per stream. A stalled Dispatch is never fatal here: it
// is itself the leak, and the settle-poll prints its stack.
func leakAwaitDispatch(t *testing.T, streams []*leakStream) bool {
	t.Helper()
	deadline := time.Now().Add(leakSettleTimeout)
	stalled := false
	for index, stream := range streams {
		// A spent budget yields a non-positive duration, so the timer fires at
		// once and the remaining streams are reported without further waiting.
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-stream.done:
		case <-timer.C:
			t.Errorf("Dispatch %d did not return after teardown", index)
			stalled = true
		}
		timer.Stop()
	}
	return stalled
}

// leakClose closes the client within a bounded window.
//
// Client.Close walks Session.Close -> fail() -> closeOnce and then loops.Wait().
// If a session is already wedged inside that once, or a carrier loop cannot
// unwind, a second entrant blocks forever and takes the entire test binary with
// it — a 120s package hang instead of a reported leak. A leak gate has to
// survive its own red run, so an unresponsive Close is abandoned rather than
// waited on. The abandoned goroutine stays visible to the settle-poll, where its
// stack points straight at the wedge.
func leakClose(t *testing.T, client *Client) {
	t.Helper()
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	timer := time.NewTimer(leakSettleTimeout)
	defer timer.Stop()
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("client close: %v", err)
		}
	case <-timer.C:
		t.Errorf("client.Close did not return within %s; abandoning it", leakSettleTimeout)
	}
}

// TestSMUXLifecycleDoesNotLeakGoroutines is the resource-leak regression gate
// for the SMUX client/service pair. It drives a complete lifecycle — carrier
// handshake, concurrent streams, bidirectional transfer, teardown — and fails
// with the offending stacks when teardown does not reclaim what it started.
func TestSMUXLifecycleDoesNotLeakGoroutines(t *testing.T) {
	scenarios := []struct {
		name   string
		abrupt bool
	}{
		{name: "graceful close"},
		{name: "abrupt carrier close", abrupt: true},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			baseline := leakOwnedGoroutines()
			goroutinesBefore := runtime.NumGoroutine()

			dispatcher := &echoDispatcher{target: make(chan X.Destination, leakStreamCount)}
			dialer := &leakCarrierDialer{service: NewService(dispatcher)}
			client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxConnections: 1})
			if err != nil {
				t.Fatal(err)
			}
			// Bounded: this fires on every t.Fatal path, which is exactly when a
			// session is most likely to be wedged.
			defer leakClose(t, client)

			destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
			streams := leakOpenStreams(t, client, destination)
			for index, stream := range streams {
				leakEcho(t, stream, leakPayload(index))
			}
			leakAssertMeasuring(t, baseline, dialer, leakStreamCount)

			if scenario.abrupt {
				// Die with queued frames on both sides rather than on an idle
				// session: the cleanup-skipping paths are the ones reached while
				// work is still in flight.
				for index, stream := range streams {
					leakWrite(t, stream, leakPayload(index+len(streams)))
				}
				dialer.slam()
			}
			for _, stream := range streams {
				stream.cancel()
			}
			// A stalled Dispatch means something is already wedged; re-entering
			// Close from here can block on the same closeOnce and hang the whole
			// test binary, so the assertion is bounded and the goroutine
			// abandoned instead.
			if !leakAwaitDispatch(t, streams) {
				leakClose(t, client)
			}

			leaked, carriers := leakAwaitSettled(t, baseline, dialer)
			leakReport(t, scenario.name, goroutinesBefore, runtime.NumGoroutine(), leaked, carriers)
		})
	}
}

// TestSMUXCarrierDeathReleasesServiceStreamHandlers covers the teardown path
// the lifecycle gate above cannot reach: a carrier that dies while the service
// still has stream handlers inside the dispatcher.
//
// Service.NewConnection tears down with `defer { session.Close(); handlers.Wait() }`,
// and handleStream dispatches on a context derived from the *carrier* context.
// Nothing cancels that context when the session dies, so a dispatcher parked on
// work that is not the stream's own I/O — an outbound dial, most realistically —
// never learns the carrier is gone. handlers.Wait() then blocks forever and the
// whole service goroutine set for that carrier is stranded.
//
// blockingServiceDispatcher stands in for such a dispatcher: it is well behaved
// and unwinds on ctx.Done(), so anything left running here is the service
// failing to cancel, not the dispatcher misbehaving.
func TestSMUXCarrierDeathReleasesServiceStreamHandlers(t *testing.T) {
	baseline := leakOwnedGoroutines()
	goroutinesBefore := runtime.NumGoroutine()

	dispatcher := &blockingServiceDispatcher{
		echoDispatcher: &echoDispatcher{target: make(chan X.Destination, leakStreamCount)},
		started:        make(chan struct{}, leakStreamCount),
		finished:       make(chan struct{}, leakStreamCount),
		// Deliberately never closed: only context cancellation may release these
		// handlers, which is precisely what the carrier teardown owes them.
		release: make(chan struct{}),
	}
	// Runs strictly after the settle-poll and report below, so it cannot mask
	// the failure it exists to survive: on a red run this keeps the stranded
	// handlers from polluting whichever test the binary runs next.
	t.Cleanup(func() { close(dispatcher.release) })
	dialer := &leakCarrierDialer{service: NewService(dispatcher)}
	client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Bounded: this fires on every t.Fatal path, which is exactly when a session
	// is most likely to be wedged.
	defer leakClose(t, client)

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	streams := leakOpenStreams(t, client, destination)
	for index := range streams {
		select {
		case <-dispatcher.started:
		case <-time.After(leakSettleTimeout):
			t.Fatalf("stream %d never reached the dispatcher", index)
		}
	}
	leakAssertMeasuring(t, baseline, dialer, leakStreamCount)

	dialer.slam()
	for _, stream := range streams {
		stream.cancel()
	}
	if !leakAwaitDispatch(t, streams) {
		leakClose(t, client)
	}

	leaked, carriers := leakAwaitSettled(t, baseline, dialer)
	leakReport(t, "carrier death with dispatch in flight", goroutinesBefore, runtime.NumGoroutine(), leaked, carriers)
}
