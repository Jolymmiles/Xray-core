// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"errors"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

const defaultMaxPendingHandshakes = 512

// A carrier that produces no bytes at all is unreachable. SMUX wire keepalive is
// disabled in both directions for interop with sing-box and mihomo peers, so
// nothing else reaps a client that vanishes without a FIN: the session read loop
// parks in io.ReadFull forever, pinning the connection, its loop goroutines and
// every buffered chunk.
//
// Reaping a carrier must never kill a stream that policy would have kept, and
// what makes that safe is containment, not a margin: idleConn wraps the *raw*
// carrier and stamps activity in both directions, so every stream's payload
// passes through it. Carrier silence therefore contains stream silence — if the
// carrier has been quiet for T, every stream on it has been quiet for at least
// T. The condition to preserve is
//
//	carrier idle timeout >= the effective connIdle policy
//
// under which policy always fires first. connIdle is operator-settable with no
// clamp (infra/conf/policy.go), so no constant can establish that on its own:
// this value is only the floor, and carrierIdleTimeoutFor derives the rest from
// the policy that applies to the carrier's own inbound user — see the residual
// documented there, which containment does not cover.
//
// Containment is a constraint to PRESERVE, and nothing in the compiler enforces
// it. Two rules follow, and breaking either silently voids the argument above
// without failing a single test:
//
//   - rawConnection stays close-only. Reading or writing it directly would move
//     payload past idleConn, and carrier silence would stop implying stream
//     silence.
//   - nothing may reap on a signal that is not downstream of all stream
//     payload. A timer keyed off session creation, a keepalive counter, or any
//     clock not fed by actual bytes breaks containment even while it looks
//     like a stricter check.
const defaultCarrierIdleTimeout = 10 * time.Minute

// The handshake watchdog is a backstop for carriers that ignore
// SetReadDeadline, not the primary bound. A carrier that does honour deadlines
// gets this much of a head start to fail its own read, so the caller keeps the
// accurate timeout error instead of a closed connection.
//
// It is added to carrierHandshakeTimeout rather than scaled with it, so a
// handshake timeout configured well below it is dominated by the grace. That is
// deliberate: undershooting the backstop would make it race the deadline it
// exists to back up, and losing that race costs the caller its error, not its
// connection.
const handshakeWatchdogGrace = 500 * time.Millisecond

// A dispatcher that ignores both its cancelled context and its failed stream is
// misbehaving. Bound the teardown wait rather than pin the carrier forever.
const defaultHandlerDrainTimeout = 30 * time.Second

type Service struct {
	dispatcher              routing.Dispatcher
	carrierHandshakeTimeout time.Duration
	streamHandshakeTimeout  time.Duration
	carrierIdleTimeout      time.Duration
	handlerDrainTimeout     time.Duration
	maxPendingHandshakes    int
	policyManager           policy.Manager
	handshakeSlotsOnce      sync.Once
	handshakeSlots          chan struct{}
}

// SetPolicy supplies the policy manager the carrier idle timeout is derived
// from. It is optional: without it the timeout stays at whatever
// carrierIdleTimeout holds, which is safe only while no operator raises
// connIdle above it. common/mux/server.go resolves the manager and calls this;
// resolving core from inside this package would risk an import cycle.
func (s *Service) SetPolicy(manager policy.Manager) {
	s.policyManager = manager
}

// carrierIdleTimeoutFor returns the idle timeout for one carrier, deriving it
// from policy instead of trusting a constant to stay above an operator-settable
// connIdle.
//
// The level is the carrier's own inbound user's, on ownership grounds only:
// every stream the carrier multiplexes belongs to that user. It is NOT the
// level that arms the timer which ends those streams — see below — so read the
// doubling as headroom over the one level knowable here, not as a margin over
// the policy that actually governs a stream.
//
// The level is available: the inbound handler populates session.Inbound.User
// during its own handshake, before it dispatches — proxy/vless/inbound:568 sets
// it and dispatches at :658, proxy/vmess/inbound:274 likewise. Anonymous
// inbounds leave it nil and fall back to level 0. Without that ordering the
// derivation would silently degrade to level 0 and enforce nothing while every
// test still passed.
//
// A non-positive carrierIdleTimeout means the watchdog is switched off, and
// stays off: derivation raises the timeout, it never enables one.
//
// # What this does NOT enforce
//
// The connIdle that ends a dispatched stream is resolved by the outbound proxy
// routing selects for that stream, and which level that proxy uses varies by
// proxy type — this is not one call site to go fix:
//
//	proxy/freedom/freedom.go:227         ForLevel(h.config.UserLevel)  — the outbound handler's own JSON
//	                                     (infra/conf/freedom.go:23 → :159); freedom reads
//	                                     InboundFromContext at :263 and :441, never for the level
//	proxy/vless/outbound/outbound.go:297 ForLevel(request.User.Level)  — the remote server's user
//	proxy/vmess/inbound/inbound.go:276   ForLevel(request.User.Level)  — the inbound user
//
// The inbound user's level and the outbound handler's level are independent
// knobs. Routing picks the outbound per stream per destination, so no single
// governing level exists at carrier setup and none of this is derivable here.
// The reap is unsafe if and only if
//
//	connIdle(outboundLevel) > max(defaultCarrierIdleTimeout, 2 × connIdle(inboundUserLevel))
//
// one-directional, because derivation only ever raises the carrier window.
// Stock configuration is safe with headroom: 300s inbound gives a 600s carrier
// against a 300s outbound. Breaking it takes a deliberately asymmetric config,
// and this one is reachable —
//
//	inbound users at level 0, connIdle 300s ⇒ carrier max(600s, 2×300s) = 600s
//	outbound freedom with userLevel 7, policy.levels.7.connIdle 3600 ⇒ stream timer 3600s
//	⇒ the carrier is reaped at 600s against a 3600s intent
//
// An operator can check that inequality against their own config; "not fully
// enforced" is not something they could act on, which is why it is written as
// one.
//
// Containment (see defaultCarrierIdleTimeout) does not rescue this case and
// must not be read as if it did: containment holds the carrier window against
// the stream's *governing* connIdle, and it is exactly that precondition which
// the inequality above breaks.
func (s *Service) carrierIdleTimeoutFor(ctx context.Context) time.Duration {
	if s.carrierIdleTimeout <= 0 || s.policyManager == nil {
		return s.carrierIdleTimeout
	}
	level := uint32(0)
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		level = inbound.User.Level
	}
	if derived := 2 * s.policyManager.ForLevel(level).Timeouts.ConnectionIdle; derived > s.carrierIdleTimeout {
		return derived
	}
	return s.carrierIdleTimeout
}

// idleConn records carrier activity for the idle watchdog in NewConnection.
//
// It deliberately does not use SetReadDeadline. Every carrier that reaches
// Service.NewConnection in production is a *cnc.Connection — common/mux/server.go
// builds one in both dispatchSMUX and DispatchLink — and all three of its
// Set*Deadline methods are no-op stubs returning nil. A deadline-based idle
// guard compiles, runs and never fires there.
//
// Both directions count. A server->client download carries outbound frames and
// no inbound ones for as long as it runs (mplsmux acknowledges nothing), so
// tracking reads alone would reap live transfers.
type idleConn struct {
	net.Conn
	lastActivity atomic.Int64 // unix nanos, written by the read and write loops
}

func (c *idleConn) touch() {
	c.lastActivity.Store(time.Now().UnixNano())
}

func (c *idleConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleConn) Write(payload []byte) (int, error) {
	n, err := c.Conn.Write(payload)
	if n > 0 {
		c.touch()
	}
	return n, err
}

// idleFor reports how long the carrier has been silent as of now.
func (c *idleConn) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, c.lastActivity.Load()))
}

func (s *Service) pendingHandshakeSlots() chan struct{} {
	s.handshakeSlotsOnce.Do(func() {
		limit := s.maxPendingHandshakes
		if limit <= 0 {
			limit = defaultMaxPendingHandshakes
		}
		s.handshakeSlots = make(chan struct{}, limit)
	})
	return s.handshakeSlots
}

func NewService(dispatcher routing.Dispatcher) *Service {
	return &Service{
		dispatcher:              dispatcher,
		carrierHandshakeTimeout: handshakeTimeout,
		streamHandshakeTimeout:  handshakeTimeout,
		carrierIdleTimeout:      defaultCarrierIdleTimeout,
		handlerDrainTimeout:     defaultHandlerDrainTimeout,
		maxPendingHandshakes:    defaultMaxPendingHandshakes,
	}
}

// handlerGroup counts live stream handlers.
//
// sync.WaitGroup would do the counting, but its Wait cannot be bounded without
// parking a goroutine on it — and on a carrier whose dispatcher never returns,
// that waiter is leaked on top of the handler it is waiting for, once per such
// carrier. Here the last handler to leave closes the drain channel itself, so
// bounding the wait costs nothing and the only residue left by a stalled
// teardown is the misbehaving handler.
//
// The zero value is ready to use.
type handlerGroup struct {
	mu      sync.Mutex
	count   int
	drained chan struct{}
	closed  bool
}

func (g *handlerGroup) add() {
	g.mu.Lock()
	g.count++
	g.mu.Unlock()
}

func (g *handlerGroup) done() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.count--
	// Only once teardown has asked: before that the group empties between two
	// streams all the time, and reporting that as drained would be wrong.
	if g.count == 0 && g.drained != nil {
		g.closeLocked()
	}
}

// drain returns a channel closed once every handler has returned. It belongs to
// teardown: no handler may be added after it, which holds because the only
// caller of add is the accept loop, and that loop has returned by the time the
// deferred tearDown runs.
func (g *handlerGroup) drain() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.drained == nil {
		g.drained = make(chan struct{})
	}
	if g.count == 0 {
		g.closeLocked()
	}
	return g.drained
}

// closeLocked is idempotent: drain may be called more than once, and it races
// the last done.
func (g *handlerGroup) closeLocked() {
	if !g.closed {
		g.closed = true
		close(g.drained)
	}
}

// tearDown releases everything the carrier owns. The order is the only one that
// works: cancel first, so a dispatcher that only observes its context unblocks;
// close the session second, so one that only notices stream I/O sees its reads
// and writes fail; drain the handlers last, which keeps the caller from closing
// the carrier out from under a live one.
//
// There is deliberately no walk of the accept backlog. Session.Close fails the
// session, and fail() drains every registered stream — including those still
// parked in accepts, which acceptRemoteStream registers before handing them
// over. Closing them one by one first was both slow and futile: mplsmux bounds
// Stream.Close only by its 30s closeTimeout, so on a stalled carrier the first
// queued stream pinned teardown for the full 30s, by which point the drain's
// own 10ms accept deadline had expired and the remaining backlog was abandoned
// unclosed anyway.
func (s *Service) tearDown(session *mplsmux.Session, cancelHandlers context.CancelFunc, handlers *handlerGroup) {
	cancelHandlers()
	_ = session.Close()
	timer := time.NewTimer(s.handlerDrainTimeout)
	defer timer.Stop()
	select {
	case <-handlers.drain():
	case <-timer.C:
	}
}

func (s *Service) NewConnection(ctx context.Context, connection net.Conn) error {
	if connection == nil {
		return errors.New("SMUX carrier connection is required")
	}
	if s == nil || s.dispatcher == nil {
		return errors.New("SMUX dispatcher is required")
	}
	rawConnection := connection
	// Wrapping the raw carrier rather than the padded one is what gives the
	// containment property the idle timeout relies on: every byte of every
	// stream, in both directions, passes through here.
	idleTimeout := s.carrierIdleTimeoutFor(ctx)
	var idle *idleConn
	if idleTimeout > 0 {
		idle = &idleConn{Conn: connection}
		idle.touch()
		connection = idle
	}
	// The carrier handshake below sets a read deadline that a cnc.Connection
	// ignores, so a peer that connects and then says nothing parks
	// readCarrierRequest forever — before any session exists for anything else
	// to reap. This bound is deliberately not conditional on the idle watchdog:
	// a Service with carrierIdleTimeout zeroed must still lose the handshake
	// bound with it. (No such construction exists in-tree — common/mux/server.go
	// is the only caller and it uses NewService — but Service is exported.)
	handshakeBound := s.carrierHandshakeTimeout
	if handshakeBound <= 0 {
		handshakeBound = handshakeTimeout
	}
	handshakeBound += handshakeWatchdogGrace
	handshakeDone := make(chan struct{})
	watchDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		// One goroutine covers all three deadlines, because all three react the
		// same way — close the raw carrier — and this one is already joined
		// before NewConnection returns, which the other two need just as much.
		// Phase 1 bounds the handshake; phase 2 is the idle watchdog.
		timer := time.NewTimer(handshakeBound)
		defer timer.Stop()
		expiry := timer.C
		// A private copy: disabling this case must not touch the variable the
		// handshake closes, which the closure would otherwise share with it.
		handshaked := handshakeDone
		for {
			select {
			case <-ctx.Done():
				_ = rawConnection.Close()
				return
			case <-watchDone:
				return
			case <-handshaked:
				handshaked = nil
				timer.Stop()
				if idle == nil {
					// Nothing left to bound; keep watching the context only.
					expiry = nil
					continue
				}
				// The handshake bytes have just landed, so the idle window
				// starts now and the case below refines it from there.
				timer.Reset(idleTimeout)
			case now := <-expiry:
				if handshaked != nil {
					// Phase 1: the carrier handshake overran its bound.
					_ = rawConnection.Close()
					return
				}
				// Sleep for whatever the carrier has left instead of polling, so an
				// active carrier costs one wakeup per idle period. The floor keeps a
				// hair's worth of remaining time from busy-resetting the timer.
				remaining := idleTimeout - idle.idleFor(now)
				if remaining < time.Millisecond {
					_ = rawConnection.Close()
					return
				}
				timer.Reset(remaining)
			}
		}
	}()
	// Join the watcher instead of only signalling it. An unsynchronised watcher
	// can still close the carrier after NewConnection has returned, which races
	// the caller's own close of that connection.
	defer func() {
		close(watchDone)
		<-watcherDone
	}()

	deadline := time.Now().Add(s.carrierHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetReadDeadline(deadline)
	request, err := readCarrierRequest(connection)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	_ = connection.SetReadDeadline(time.Time{})
	close(handshakeDone)
	if request.Version == carrierVersionPadded {
		connection = newPaddingConn(connection)
	}
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := mplsmux.Server(connection, config)
	if err != nil {
		return err
	}

	// Stream handlers must be stoppable independently of the carrier context:
	// the carrier can die while the parent context stays live, and NewConnection
	// waits for its handlers before returning.
	handlerCtx, cancelHandlers := context.WithCancel(ctx)
	handshakeSlots := s.pendingHandshakeSlots()
	var handlers handlerGroup
	defer s.tearDown(session, cancelHandlers, &handlers)
	for {
		stream, acceptErr := session.AcceptStream()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return acceptErr
		}
		select {
		case handshakeSlots <- struct{}{}:
			handlers.add()
			go func() {
				defer handlers.done()
				s.handleStream(handlerCtx, stream, handshakeSlots)
			}()
		case <-ctx.Done():
			// Abort, not Close: nothing has cancelled or failed the session yet,
			// so Close would submit a frameClose bounded only by mplsmux's 30s
			// closeTimeout and park here on a stalled carrier — before tearDown
			// spends its own drain bound. ctx.Err() is the truer error anyway.
			_ = stream.Abort()
			return ctx.Err()
		case <-session.CloseChan():
			// Close is safe here: the session is already failed, so the submit
			// short-circuits on IsClosed rather than waiting for the carrier.
			_ = stream.Close()
			return net.ErrClosed
		default:
			// Abort fails the whole session when the control queue is full, so the
			// error must not be swallowed: report it instead of spinning on an
			// AcceptStream that is about to fail anyway.
			if err := stream.Abort(); err != nil {
				return err
			}
		}
	}
}

func (s *Service) handleStream(ctx context.Context, stream net.Conn, handshakeSlots chan struct{}) {
	defer stream.Close()
	flags, destination, err := s.handshakeStream(ctx, stream)
	<-handshakeSlots
	if err != nil {
		return
	}

	var reader buf.Reader = buf.NewReader(stream)
	var writer buf.Writer = buf.NewWriter(stream)
	if flags&streamFlagUDP != 0 {
		reader = &packetReader{stream: stream}
		writer = &packetWriter{stream: stream, destination: destination}
	}
	_ = s.dispatcher.DispatchLink(streamContext(ctx), destination, &transport.Link{Reader: reader, Writer: writer})
}

// streamContext gives one carrier stream its own Outbound and Content.
//
// The carrier context is shared by every stream of the session, and the
// dispatcher, router and outbound handlers all write through those pointers
// (Outbound.Target, Content.SkipSniffingAttributes, ...). Dispatching every
// stream on the carrier context makes those writes alias, which races reads in
// the router matchers and the dialer, and can panic once a matcher observes an
// IP target replaced by a domain between the family check and the read.
//
// Equivalent to session.SubContextFromMuxInbound, except that helper panics on
// a carrier that already holds attributes. That is reachable here: an HTTP
// inbound sets sniffed attributes before dispatching to a client-supplied
// destination, which may be the SMUX one. Clone them per stream instead.
func streamContext(parent context.Context) context.Context {
	content := session.Content{}
	if carrier := session.ContentFromContext(parent); carrier != nil {
		content = *carrier
		content.Attributes = maps.Clone(carrier.Attributes)
	}
	return session.ContextWithContent(session.ContextWithOutbounds(parent, []*session.Outbound{{}}), &content)
}

func (s *Service) handshakeStream(ctx context.Context, stream net.Conn) (uint16, X.Destination, error) {
	deadline := time.Now().Add(s.streamHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = stream.SetReadDeadline(deadline)
	flags, destination, err := readStreamRequest(stream)
	if err != nil {
		return 0, X.Destination{}, err
	}
	_ = stream.SetReadDeadline(time.Time{})
	if err := writeStreamResponse(stream, nil); err != nil {
		return 0, X.Destination{}, err
	}
	return flags, destination, nil
}
