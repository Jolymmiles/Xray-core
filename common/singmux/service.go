// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"errors"
	"maps"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

const defaultMaxPendingHandshakes = 512

// A carrier that produces no bytes at all is unreachable. SMUX wire keepalive is
// disabled in both directions for interop with sing-box and mihomo peers, so
// nothing else reaps a client that vanishes without a FIN: the session read loop
// parks in io.ReadFull forever, pinning the connection, its loop goroutines and
// every buffered chunk. The default sits far above Xray's 300s connIdle policy,
// so any stream still alive on this carrier has seen traffic much more recently.
const defaultCarrierIdleTimeout = 10 * time.Minute

// A dispatcher that ignores both its cancelled context and its failed stream is
// misbehaving. Bound the teardown wait rather than pin the carrier forever.
const defaultHandlerDrainTimeout = 30 * time.Second

// Queued-but-unaccepted streams are collected with a deadline in the future, so
// that each already-queued stream wins its select immediately and only the final
// empty wait is bounded.
const acceptDrainTimeout = 10 * time.Millisecond

// Upper bound on that drain. A peer that keeps opening streams while the carrier
// is being torn down must not be able to hold the drain loop open and postpone
// the close indefinitely. Matches the session accept backlog.
const maxAcceptDrain = 512

type Service struct {
	dispatcher              routing.Dispatcher
	carrierHandshakeTimeout time.Duration
	streamHandshakeTimeout  time.Duration
	carrierIdleTimeout      time.Duration
	handlerDrainTimeout     time.Duration
	maxPendingHandshakes    int
	handshakeSlotsOnce      sync.Once
	handshakeSlots          chan struct{}
}

// idleConn fails reads on a carrier that has gone completely silent. Reads are
// issued only by the single session read loop, so the refresh bookkeeping needs
// no lock.
type idleConn struct {
	net.Conn
	timeout     time.Duration
	lastRefresh time.Time
}

func (c *idleConn) Read(payload []byte) (int, error) {
	// Refresh lazily: a deadline syscall on every frame would land in the carrier
	// hot path and buy nothing, since the timeout is minutes wide.
	if now := time.Now(); now.Sub(c.lastRefresh) >= c.timeout/4 {
		if err := c.Conn.SetReadDeadline(now.Add(c.timeout)); err != nil {
			return 0, err
		}
		c.lastRefresh = now
	}
	return c.Conn.Read(payload)
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

// drainAcceptBacklog closes streams the peer opened but the accept loop never
// handed to a handler. It must run before the session is closed: AcceptStream on
// a closed session reports the terminal error and drops any queued stream
// without closing it, leaking that stream's receive buffers.
func (s *Service) drainAcceptBacklog(session *mplsmux.Session) {
	if session.IsClosed() {
		return
	}
	_ = session.SetDeadline(time.Now().Add(acceptDrainTimeout))
	for range maxAcceptDrain {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		_ = stream.Close()
	}
}

// waitBounded waits for the handler group, but not forever. If the bound
// expires, one waiter goroutine is left behind instead of the carrier
// connection, its accept goroutine and every remaining handler.
func waitBounded(handlers *sync.WaitGroup, timeout time.Duration) {
	finished := make(chan struct{})
	go func() {
		handlers.Wait()
		close(finished)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-finished:
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
	watchDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = rawConnection.Close()
		case <-watchDone:
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
	if request.Version == carrierVersionPadded {
		connection = newPaddingConn(connection)
	}
	if s.carrierIdleTimeout > 0 {
		connection = &idleConn{Conn: connection, timeout: s.carrierIdleTimeout}
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
	var handlers sync.WaitGroup
	defer func() {
		// Cancel first, so a dispatcher that only observes its context unblocks;
		// close second, so a dispatcher that only notices stream I/O sees its
		// reads and writes fail. Both must precede Wait, which in turn keeps the
		// caller from closing the carrier out from under a live handler.
		cancelHandlers()
		// Collect queued-but-unhandled streams while the session can still hand
		// them over, then fail the session, then wait.
		s.drainAcceptBacklog(session)
		_ = session.Close()
		waitBounded(&handlers, s.handlerDrainTimeout)
	}()
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
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				s.handleStream(handlerCtx, stream, handshakeSlots)
			}()
		case <-ctx.Done():
			_ = stream.Close()
			return ctx.Err()
		case <-session.CloseChan():
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
