// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"errors"
	"io"
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

type Service struct {
	dispatcher              routing.Dispatcher
	presenceProvider        session.PresenceProvider
	carrierHandshakeTimeout time.Duration
	streamHandshakeTimeout  time.Duration
	maxPendingHandshakes    int
	handshakeSlotsOnce      sync.Once
	handshakeSlots          chan struct{}
	setBrutalOptions        func(net.Conn, uint64) error

	lifecycleOnce sync.Once
	lifecycleMu   sync.Mutex
	lifecycleCond *sync.Cond
	closing       bool
	carriers      map[*serviceCarrier]struct{}
	closeDone     chan struct{}
	closeErr      error
}

type serviceCarrier struct {
	net.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	closeOnce   sync.Once
	closeErr    error
	handlerMu   sync.Mutex
	handlerCond *sync.Cond
	stopping    bool
	handlers    int
}

func (c *serviceCarrier) Close() error {
	c.closeOnce.Do(func() {
		c.handlerMu.Lock()
		c.stopping = true
		c.handlerMu.Unlock()
		// Cancel stream work before physical close makes the protocol loops exit
		// and NewConnection starts waiting for handlers.
		c.cancel()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *serviceCarrier) beginHandler() bool {
	c.handlerMu.Lock()
	defer c.handlerMu.Unlock()
	if c.stopping {
		return false
	}
	c.handlers++
	return true
}

func (c *serviceCarrier) finishHandler() {
	c.handlerMu.Lock()
	c.handlers--
	c.handlerCond.Broadcast()
	c.handlerMu.Unlock()
}

func (c *serviceCarrier) waitHandlers() {
	c.handlerMu.Lock()
	for c.handlers != 0 {
		c.handlerCond.Wait()
	}
	c.handlerMu.Unlock()
}

func (s *Service) initLifecycle() {
	s.lifecycleOnce.Do(func() {
		s.lifecycleCond = sync.NewCond(&s.lifecycleMu)
		s.carriers = make(map[*serviceCarrier]struct{})
		s.closeDone = make(chan struct{})
	})
}

func (s *Service) admitCarrier(ctx context.Context, connection net.Conn) (*serviceCarrier, error) {
	s.initLifecycle()
	s.lifecycleMu.Lock()
	if s.closing {
		s.lifecycleMu.Unlock()
		closeErr := abnormalCloseError(connection.Close())
		return nil, errors.Join(net.ErrClosed, closeErr)
	}
	carrierCtx, cancel := context.WithCancel(ctx)
	carrier := &serviceCarrier{Conn: connection, ctx: carrierCtx, cancel: cancel}
	carrier.handlerCond = sync.NewCond(&carrier.handlerMu)
	s.carriers[carrier] = struct{}{}
	s.lifecycleMu.Unlock()
	return carrier, nil
}

func (s *Service) releaseCarrier(carrier *serviceCarrier) {
	_ = carrier.Close()
	carrier.waitHandlers()
	s.lifecycleMu.Lock()
	delete(s.carriers, carrier)
	s.lifecycleCond.Broadcast()
	s.lifecycleMu.Unlock()
}

func abnormalCloseError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var abnormal []error
		for _, child := range joined.Unwrap() {
			if child = abnormalCloseError(child); child != nil {
				abnormal = append(abnormal, child)
			}
		}
		return errors.Join(abnormal...)
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		child := wrapped.Unwrap()
		filtered := abnormalCloseError(child)
		if filtered == nil {
			return nil
		}
		if errors.Is(child, net.ErrClosed) || errors.Is(child, io.ErrClosedPipe) {
			return filtered
		}
		return err
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

// Close stops carrier admission, interrupts every admitted carrier, and waits
// until every NewConnection call has reached terminal completion.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.initLifecycle()
	s.lifecycleMu.Lock()
	if s.closing {
		done := s.closeDone
		s.lifecycleMu.Unlock()
		<-done
		return s.closeErr
	}
	s.closing = true
	carriers := make([]*serviceCarrier, 0, len(s.carriers))
	for carrier := range s.carriers {
		carriers = append(carriers, carrier)
	}
	s.lifecycleMu.Unlock()

	closeResults := make(chan error, len(carriers))
	for _, carrier := range carriers {
		go func() { closeResults <- abnormalCloseError(carrier.Close()) }()
	}
	var closeErrors []error
	for range carriers {
		if err := <-closeResults; err != nil {
			closeErrors = append(closeErrors, err)
		}
	}

	s.lifecycleMu.Lock()
	for len(s.carriers) != 0 {
		s.lifecycleCond.Wait()
	}
	s.closeErr = errors.Join(closeErrors...)
	close(s.closeDone)
	s.lifecycleMu.Unlock()
	return s.closeErr
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
	service := &Service{
		dispatcher:              dispatcher,
		carrierHandshakeTimeout: handshakeTimeout,
		streamHandshakeTimeout:  handshakeTimeout,
		maxPendingHandshakes:    defaultMaxPendingHandshakes,
		setBrutalOptions:        SetBrutalOptions,
	}
	if source, ok := dispatcher.(session.PresenceProviderSource); ok {
		service.presenceProvider = source.PresenceProvider()
	}
	return service
}

func (s *Service) NewConnection(ctx context.Context, connection net.Conn) error {
	if connection == nil {
		return errors.New("SMUX carrier connection is required")
	}
	if s == nil || s.dispatcher == nil {
		_ = connection.Close()
		return errors.New("SMUX dispatcher is required")
	}
	parentCtx := ctx
	carrier, err := s.admitCarrier(parentCtx, connection)
	if err != nil {
		return err
	}
	defer s.releaseCarrier(carrier)
	connection = carrier
	ctx = carrier.ctx
	stopParentClose := context.AfterFunc(parentCtx, func() { _ = carrier.Close() })
	defer func() {
		if !stopParentClose() {
			_ = carrier.Close()
		}
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
	// Version 1 option 0 explicitly keeps the carrier raw.
	if request.Padding != nil {
		connection = newPaddingConn(connection)
	}
	presence := session.PresenceScope{}
	if s.presenceProvider != nil {
		presence = s.presenceProvider.SnapshotPresence(ctx)
	}
	brutal := newServerBrutalController(ctx, s.setBrutalOptions)
	brutal.closeCarrier = carrier.Close
	if request.Protocol == protocolH2MUX {
		return s.serveH2Mux(ctx, connection, carrier, brutal, presence)
	}
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := mplsmux.Server(connection, config)
	if err != nil {
		return err
	}

	handshakeSlots := s.pendingHandshakeSlots()
	defer func() { _ = session.Close() }()
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
			if !carrier.beginHandler() {
				<-handshakeSlots
				_ = stream.Abort()
				continue
			}
			go func() {
				defer carrier.finishHandler()
				s.handleStream(ctx, stream, handshakeSlots, brutal, presence)
			}()
		case <-ctx.Done():
			_ = stream.Close()
			return ctx.Err()
		case <-session.CloseChan():
			_ = stream.Close()
			return net.ErrClosed
		default:
			_ = stream.Abort()
		}
	}
}

func (s *Service) handleStream(ctx context.Context, stream net.Conn, handshakeSlots chan struct{}, brutal *serverBrutalController, presence session.PresenceScope) {
	defer stream.Close()
	flags, destination, err := s.handshakeStream(ctx, stream)
	<-handshakeSlots
	if err != nil {
		return
	}
	if isBrutalDestination(destination) {
		if flags&streamFlagUDP != 0 || destination.Network != X.Network_TCP || destination.Port != 0 {
			_ = writeBrutalResponse(stream, 0, false, "invalid Brutal control destination")
			return
		}
		closeCarrier, _ := brutal.handle(ctx, stream, s.streamDeadline(ctx))
		if closeCarrier && brutal.closeCarrier != nil {
			_ = brutal.closeCarrier()
		}
		return
	}

	var reader buf.Reader = buf.NewReader(stream)
	var writer buf.Writer = buf.NewWriter(stream)
	if flags&streamFlagUDP != 0 {
		reader = &packetReader{stream: stream}
		writer = &packetWriter{stream: stream, destination: destination}
	}
	lease := presence.Prepare().Activate()
	defer lease.Close()
	streamCtx := session.ContextWithPresenceMode(streamContext(ctx), session.PresenceModeExternal)
	_ = s.dispatcher.DispatchLink(streamCtx, destination, &transport.Link{Reader: reader, Writer: writer})
}

func (s *Service) streamDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(s.streamHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
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
	_ = stream.SetDeadline(s.streamDeadline(ctx))
	defer stream.SetDeadline(time.Time{})
	flags, destination, err := readStreamRequest(stream)
	if err != nil {
		return 0, X.Destination{}, err
	}
	if err := writeStreamResponse(stream, nil); err != nil {
		return 0, X.Destination{}, err
	}
	return flags, destination, nil
}
