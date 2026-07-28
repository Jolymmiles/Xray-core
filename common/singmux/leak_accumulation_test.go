// SPDX-License-Identifier: MPL-2.0

// Untagged on purpose, exactly like leak_integration_test.go: this is the
// accumulation half of the resource-leak gate, so it has to run in the default
// `go test -race ./common/singmux/` pass rather than behind an opt-in tag.
//
// The lifecycle gate next door proves one carrier reclaims what it started.
// That is not the same question as: does the service accumulate across many
// carriers whose peers vanish while their dispatchers are still parked? A
// per-carrier residue is invisible at N=1 and fatal at N=10000.
//
// The dispatcher here is never released by the test. Releasing it before the
// assertion is precisely the masking this gate exists to rule out: a handler
// that the test itself frees proves nothing about whether the service frees it.

package singmux

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

const (
	// The two sample points the accumulation question is asked between: whatever
	// the first ten carriers cost is the fixed price; carriers 11..50 must add
	// nothing to it.
	accumCarrierCount  = 50
	accumSampleCarrier = 10
	// Two streams per carrier keeps a per-stream residue and a per-carrier
	// residue distinguishable in the reported numbers.
	accumStreamsPerCarrier = 2
	// Short enough to run 50 carriers, wide enough that the reap under test is
	// the idle mechanism and not a race with the carrier handshake.
	accumIdleTimeout  = 250 * time.Millisecond
	accumStartTimeout = 5 * time.Second
	// A sample is taken once the owned-goroutine set stops shrinking. It cannot
	// wait for zero: on a leaking build there is no quiescent point to wait for,
	// and a gate that hangs instead of failing reports nothing.
	accumSettleBudget = 15 * time.Second
	accumSettleStep   = 100 * time.Millisecond
	accumSettleStable = 3
	// Tolerances are deliberately far below what one leaked carrier costs (its
	// read loop, write loop, accept loop, carrier watcher and two parked
	// handlers — six goroutines and one pinned conn), so a single leaked carrier
	// cannot hide inside the slack.
	accumGoroutineTolerance = 2
	accumCarrierTolerance   = 1
	// The D25 subtest below runs fewer carriers: it asks a per-carrier question,
	// not an accumulation one, and every carrier costs a full policy delay.
	accumPolicyCarriers = 10
	// Stands in for Timeouts.ConnectionIdle, 300s in SessionDefault
	// (features/policy/policy.go:131). Long enough that the handler is still
	// parked when the harness checks it is measuring something, short enough to
	// run ten carriers.
	accumPolicyDelay = 500 * time.Millisecond
	// Twenty times the delay: wide enough that a slow machine cannot fake a
	// refutation, tight enough that a handler which never returns is still
	// reported as a failure rather than waited on until the package times out.
	accumPolicyBudget = 10 * time.Second
	// A carrier that is deliberately never reaped still runs its read loop, write
	// loop, accept loop and watcher. Four is therefore the floor for a live
	// carrier, and six — the four plus two parked handlers — is what a leaked one
	// costs.
	accumLiveCarrierGoroutines = 4
)

// accumCarrier is the service-side end of a carrier whose peer vanished without
// a FIN — the case SMUX keepalive would have caught and cannot, because it is
// disabled in both directions for sing-box/mihomo interop
// (service.go:362, client.go:328).
//
// It is deliberately deadline-blind: SetReadDeadline is a silent no-op stub that
// reports success. That is the production shape, not a contrivance — every
// carrier reaching Service.NewConnection is a *cnc.Connection, whose Set*Deadline
// methods are all no-op stubs. The current watchdog does not depend on deadlines
// (it stamps activity on Read and Write instead), so this shape is reaped today;
// keeping it is what would catch a regression back to a deadline-based guard.
//
// Reads park rather than error, and are released only by Close — which is what a
// working reaper must do to the raw carrier.
type accumCarrier struct {
	net.Conn

	stalled   atomic.Bool
	closeOnce sync.Once
	closed    chan struct{}
	wasClosed atomic.Bool
}

func newAccumCarrier(conn net.Conn) *accumCarrier {
	return &accumCarrier{Conn: conn, closed: make(chan struct{})}
}

// stall makes the peer disappear. Called only once the handlers are parked in
// the dispatcher, so the carrier and stream handshakes complete normally first.
func (c *accumCarrier) stall() { c.stalled.Store(true) }

func (c *accumCarrier) Read(payload []byte) (int, error) {
	if !c.stalled.Load() {
		count, err := c.Conn.Read(payload)
		// A read that was already in flight when the peer vanished must not
		// deliver its result or its EOF: that EOF would tear the session down
		// for a reason a silent peer never provides, turning a red run green.
		if !c.stalled.Load() {
			return count, err
		}
	}
	<-c.closed
	return 0, net.ErrClosed
}

// Write swallows frames aimed at a peer that is no longer there, the way a
// kernel socket buffer does. Parking the writer instead would leak a different
// goroutine and confuse the attribution this gate is measuring.
func (c *accumCarrier) Write(payload []byte) (int, error) {
	if c.stalled.Load() {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		default:
			return len(payload), nil
		}
	}
	return c.Conn.Write(payload)
}

// SetReadDeadline reports success and does nothing, like the cnc.Connection this
// stands in for. Only SetReadDeadline is overridden because it is the only
// deadline setter Service.NewConnection uses (to bound the carrier handshake).
func (c *accumCarrier) SetReadDeadline(time.Time) error { return nil }

func (c *accumCarrier) Close() error {
	c.closeOnce.Do(func() {
		c.wasClosed.Store(true)
		close(c.closed)
	})
	return c.Conn.Close()
}

// accumTracker counts carrier ends teardown never closed. One pinned carrier is
// one leaked session: exact, portable and free of GC noise, unlike a heap
// reading, which this file reports as evidence but never gates on.
type accumTracker struct {
	mu       sync.Mutex
	carriers []*accumCarrier
}

func (t *accumTracker) add(carrier *accumCarrier) {
	t.mu.Lock()
	t.carriers = append(t.carriers, carrier)
	t.mu.Unlock()
}

// closeAll releases whatever the service did not. It runs from t.Cleanup, i.e.
// strictly after the assertions, so it cannot mask what it is cleaning up — and
// without it the armed check below would strand its carriers and their
// goroutines into every test that runs after it.
func (t *accumTracker) closeAll() {
	t.mu.Lock()
	carriers := append([]*accumCarrier(nil), t.carriers...)
	t.mu.Unlock()
	for _, carrier := range carriers {
		_ = carrier.Close()
	}
}

func (t *accumTracker) open() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	open := 0
	for _, carrier := range t.carriers {
		if !carrier.wasClosed.Load() {
			open++
		}
	}
	return open
}

// accumDispatcher is the handler double, in two shapes selected by policyDelay.
//
// policyDelay == 0 — the hung handler. It parks in stream I/O and never returns
// on its own, which is what every real dispatcher on this path does via
// buf.Copy while its peer is quiet. It deliberately does not select on
// ctx.Done: a handler that unwinds on cancellation would let the service pass
// without ever failing the stream. The only thing that can free it is the
// session dying, which wakes parked reads with the session's terminal error
// (stream.go:119).
//
// policyDelay > 0 — the policy-cancelled handler, standing in for a real
// outbound under signal.CancelAfterInactivity(ctx, cancel, ConnectionIdle). The
// shape matters: freedom.go:392-398 builds ctx, cancel := context.WithCancel(ctx)
// and cancels that CHILD from a closure, and vless/inbound:439-440 builds the
// identical child and passes its bare cancel. Neither cancels the context
// handleStream passed, so the double must unwind from its own derived context
// too — otherwise it would prove a propagation path that production does not use.
type accumDispatcher struct {
	started     chan struct{}
	live        atomic.Int64
	policyDelay time.Duration
}

func (*accumDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, io.ErrClosedPipe
}

func (d *accumDispatcher) DispatchLink(ctx context.Context, _ X.Destination, link *transport.Link) error {
	d.live.Add(1)
	defer d.live.Add(-1)
	d.started <- struct{}{}
	if d.policyDelay > 0 {
		idle, cancel := context.WithTimeout(ctx, d.policyDelay)
		defer cancel()
		<-idle.Done()
		return idle.Err()
	}
	for {
		buffers, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		buf.ReleaseMulti(buffers)
	}
}

func (*accumDispatcher) Start() error      { return nil }
func (*accumDispatcher) Close() error      { return nil }
func (*accumDispatcher) Type() interface{} { return routing.DispatcherType() }

// accumDialer hands out one carrier and then refuses, so retryConn cannot
// rebuild a session behind the test's back and hide what is being counted.
type accumDialer struct {
	mu   sync.Mutex
	conn net.Conn
}

func (d *accumDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		return nil, net.ErrClosed
	}
	conn := d.conn
	d.conn = nil
	return conn, nil
}

// accumService builds a Service with a test-sized idle timeout: the production
// default is 10 minutes, which 50 carriers cannot wait out. The mechanism is
// untouched, only its period — except at zero, which is how service.go itself
// switches the whole watchdog off, and which the armed check uses.
func accumService(dispatcher routing.Dispatcher, idleTimeout time.Duration) *Service {
	service := NewService(dispatcher)
	service.carrierIdleTimeout = idleTimeout
	return service
}

// accumRunCarrier drives one carrier through its whole life: handshake, streams
// parked in the dispatcher, peer vanishes, client goes away. It never releases
// the handlers.
func accumRunCarrier(t *testing.T, service *Service, dispatcher *accumDispatcher, tracker *accumTracker) {
	t.Helper()

	rawClient, rawServer := net.Pipe()
	serverConn := newAccumCarrier(rawServer)
	tracker.add(serverConn)
	go func() { _ = service.NewConnection(context.Background(), serverConn) }()

	client, err := NewClient(Options{Dialer: &accumDialer{conn: rawClient}, Protocol: "smux", MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	cancels := make([]context.CancelFunc, 0, accumStreamsPerCarrier)
	for range accumStreamsPerCarrier {
		clientLink, _ := linkPair()
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		go func() { _ = client.Dispatch(ctx, clientLink, destination) }()
	}
	for index := range accumStreamsPerCarrier {
		select {
		case <-dispatcher.started:
		case <-time.After(accumStartTimeout):
			t.Fatalf("stream %d never reached the dispatcher", index)
		}
	}
	// Without live handlers this whole gate would measure an empty teardown and
	// report success no matter what the service does.
	if live := dispatcher.live.Load(); live < accumStreamsPerCarrier {
		t.Fatalf("handlers inside the dispatcher = %d, want at least %d: the accumulation gate is not measuring anything", live, accumStreamsPerCarrier)
	}

	// The peer vanishes first, so the service never observes a FIN — then the
	// client's own resources are released normally, leaving only what the
	// service is holding.
	serverConn.stall()
	for _, cancel := range cancels {
		cancel()
	}
	leakClose(t, client)
	// rawClient is closed by client.Close; the service-side end is deliberately
	// left to the service. Closing it here is what would mask the leak.
}

// accumSample is one measurement point.
type accumSample struct {
	label      string
	goroutines map[string]string
	carriers   int
	handlers   int64
	heap       uint64
	total      int
}

// accumTake waits for the owned-goroutine set to stop shrinking, then measures.
// "Stopped shrinking" rather than "reached zero": a leaking build never reaches
// zero, and this gate has to survive its own red run.
func accumTake(label string, tracker *accumTracker, dispatcher *accumDispatcher) accumSample {
	deadline := time.Now().Add(accumSettleBudget)
	owned := leakOwnedGoroutines()
	stable := 0
	for time.Now().Before(deadline) && stable < accumSettleStable {
		time.Sleep(accumSettleStep)
		current := leakOwnedGoroutines()
		if len(current) < len(owned) {
			stable = 0
		} else {
			stable++
		}
		owned = current
	}
	// Two collections: the first drops the last generation's sync.Pool contents,
	// the second reports a heap holding only what is still referenced.
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return accumSample{
		label:      label,
		goroutines: owned,
		carriers:   tracker.open(),
		handlers:   dispatcher.live.Load(),
		heap:       stats.HeapAlloc,
		total:      runtime.NumGoroutine(),
	}
}

func (s accumSample) String() string {
	return fmt.Sprintf("%s: %d SMUX goroutines (%d total), %d unclosed carriers, %d handlers parked, heap %d KiB",
		s.label, len(s.goroutines), s.total, s.carriers, s.handlers, s.heap/1024)
}

// TestSMUXServiceDoesNotAccumulateAcrossCarriers is the accumulation gate.
//
// Fifty carriers are opened in turn. Each one gets its streams into the
// dispatcher, then its peer vanishes without a FIN while those handlers are
// still parked. The handlers are never released by the test — only the service
// failing their streams can free them.
//
// The measurement is taken between carrier 10 and carrier 50, not against a
// zero baseline: the first carriers pay one-time costs (pool warm-up, the
// client's idle sweeper) that would otherwise read as growth.
func TestSMUXServiceDoesNotAccumulateAcrossCarriers(t *testing.T) {
	scenarios := []struct {
		name        string
		idleTimeout time.Duration
		wantGrowth  bool
	}{
		// Production shape: the carrier reaper is on, and a carrier whose peer
		// vanished must not outlive it.
		{name: "carrier reaper enabled", idleTimeout: accumIdleTimeout},
		// Armed check. Same harness, same never-released dispatcher, same
		// deadline-blind carrier; the reaper is switched off exactly the way
		// service.go switches it off (carrierIdleTimeout > 0 gates the whole
		// watchdog), and the accumulation must reappear. Without this, a harness
		// that had quietly stopped measuring would be indistinguishable from a
		// fixed service. Disabled by configuration, never by neutering a
		// production path (D13).
		{name: "carrier reaper disabled (armed check)", wantGrowth: true},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			dispatcher := &accumDispatcher{started: make(chan struct{}, accumStreamsPerCarrier)}
			service := accumService(dispatcher, scenario.idleTimeout)
			tracker := &accumTracker{}
			// Registered before any carrier exists so it fires on t.Fatal paths
			// too, and it runs after the assertions, so it cannot mask them.
			t.Cleanup(tracker.closeAll)

			var early accumSample
			for carrier := 1; carrier <= accumCarrierCount; carrier++ {
				accumRunCarrier(t, service, dispatcher, tracker)
				if carrier == accumSampleCarrier {
					early = accumTake(fmt.Sprintf("after carrier %d", accumSampleCarrier), tracker, dispatcher)
				}
			}
			late := accumTake(fmt.Sprintf("after carrier %d", accumCarrierCount), tracker, dispatcher)

			// Logged on green runs too: the numbers are the evidence this gate
			// exists to produce, and they are worth nothing if only failures
			// print them.
			t.Log(early)
			t.Log(late)

			span := accumCarrierCount - accumSampleCarrier
			goroutineGrowth := len(late.goroutines) - len(early.goroutines)
			carrierGrowth := late.carriers - early.carriers
			report := func(headline string) string {
				text := fmt.Sprintf("%s\n  %s\n  %s\n  growth over %d carriers: %+d SMUX goroutines (%.1f per carrier, tolerance %d), %+d unclosed carriers (tolerance %d), %+d KiB heap",
					headline, early, late, span, goroutineGrowth, float64(goroutineGrowth)/float64(span), accumGoroutineTolerance,
					carrierGrowth, accumCarrierTolerance, (int64(late.heap)-int64(early.heap))/1024)
				for _, record := range accumStacks(early.goroutines, late.goroutines, 3) {
					text += "\n\n" + record
				}
				return text
			}

			if scenario.wantGrowth {
				// One of each per carrier is the floor that keeps the gate
				// meaningful; the observed cost is six goroutines and one carrier.
				if goroutineGrowth < span || carrierGrowth < span {
					t.Fatal(report("carrier reaper disabled and nothing accumulated: this gate has stopped measuring, so its green runs prove nothing"))
				}
				return
			}
			if goroutineGrowth <= accumGoroutineTolerance && carrierGrowth <= accumCarrierTolerance {
				return
			}
			t.Fatal(report("resources accumulate across carriers"))
		})
	}
}

// accumAwaitHandlers waits for every handler to leave the dispatcher, bounded.
// It reports whether they all did and how long it took, so a run that needed
// most of its budget is visible rather than silently green.
func accumAwaitHandlers(dispatcher *accumDispatcher, budget time.Duration) (bool, time.Duration) {
	start := time.Now()
	deadline := start.Add(budget)
	for {
		if dispatcher.live.Load() == 0 {
			return true, time.Since(start)
		}
		if !time.Now().Before(deadline) {
			return false, time.Since(start)
		}
		time.Sleep(accumSettleStep)
	}
}

// accumStacks returns up to limit stacks that appeared between the two samples,
// ordered by goroutine id so a failure reads the same way twice.
func accumStacks(early, late map[string]string, limit int) []string {
	added := leakNewGoroutines(early, late)
	ids := make([]string, 0, len(added))
	for id := range added {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	stacks := make([]string, 0, len(ids))
	for _, id := range ids {
		stacks = append(stacks, added[id])
	}
	return stacks
}

// TestSMUXPolicyCancelledHandlersReleaseTheirStreams is the D25 evidence test:
// it checks the one link in the retraction argument that was asserted rather
// than measured — that a handler cancelled by its own idle policy actually
// returns, releasing its stream, *without* the carrier being reaped.
//
// The carrier reaper is switched off for the whole test (carrierIdleTimeout=0),
// so nothing here can close a carrier. Anything reclaimed was reclaimed by the
// policy path alone, which is exactly the layering D25 rests on.
//
// How the stream count is observed. mplsmux's server-side Session is a local in
// Service.NewConnection and nothing exports it, so NumStreams() cannot be read
// directly from this package. The goroutine census proves it instead:
// handleStream runs `defer stream.Close()` and that Close is what calls
// removeStream, so the handler goroutine cannot disappear from the census until
// its stream has been removed from the session. A per-carrier residue that
// falls from six to four — the carrier's own four loops, still deliberately
// alive — therefore *is* NumStreams reaching zero, not a proxy for it.
//
// What this cannot prove: a double stands in for the outbound's policy timer,
// so this covers the service half of the chain (handler returns -> stream
// released) and not whether a real freedom/vless outbound's
// CancelAfterInactivity fires in the first place. That needs a test against a
// real outbound, which lives outside this package.
func TestSMUXPolicyCancelledHandlersReleaseTheirStreams(t *testing.T) {
	dispatcher := &accumDispatcher{
		started:     make(chan struct{}, accumStreamsPerCarrier),
		policyDelay: accumPolicyDelay,
	}
	service := accumService(dispatcher, 0)
	tracker := &accumTracker{}
	t.Cleanup(tracker.closeAll)

	for range accumPolicyCarriers {
		accumRunCarrier(t, service, dispatcher, tracker)
	}
	// The last carrier's policy timer has not fired yet when its loop iteration
	// returns, and accumTake's "stopped shrinking" heuristic cannot wait for a
	// set that has not begun shrinking — it would sample the handlers still
	// parked and report a refutation the run had not earned. Give the mechanism
	// its own bounded window first, and record how long it actually needed.
	released, elapsed := accumAwaitHandlers(dispatcher, accumPolicyBudget)
	sample := accumTake("after policy cancellation", tracker, dispatcher)
	t.Log(sample)
	if !released {
		t.Logf("handlers still parked after %s (budget %s)", elapsed.Round(time.Millisecond), accumPolicyBudget)
	}

	// Premise check first: if anything closed a carrier the result is
	// meaningless, because then the session — not the policy path — could have
	// released the streams.
	if sample.carriers != accumPolicyCarriers {
		t.Fatalf("%d of %d carriers survived, want all of them: something reaped a carrier with the watchdog disabled, so this test cannot attribute the release to the policy path",
			sample.carriers, accumPolicyCarriers)
	}
	perCarrier := float64(len(sample.goroutines)) / float64(accumPolicyCarriers)
	if sample.handlers != 0 || perCarrier > accumLiveCarrierGoroutines+1 {
		t.Fatalf("policy-cancelled handlers did not release their streams: %d still inside the dispatcher, %.1f goroutines per live carrier (want 0 and ~%d)\n  %s\n\nD25 is NOT proven: a parked stream keeps the session's stream count above zero, so the operator is owed an explicit trade rather than a resolved one",
			sample.handlers, perCarrier, accumLiveCarrierGoroutines, sample)
	}
	t.Logf("D25 holds: %d policy-cancelled handlers all returned and released their streams while every carrier stayed open; residue %.1f goroutines per live carrier (the carrier's own %d loops)",
		accumPolicyCarriers*accumStreamsPerCarrier, perCarrier, accumLiveCarrierGoroutines)
}
