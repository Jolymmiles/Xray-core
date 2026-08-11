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

type Service struct {
	dispatcher              routing.Dispatcher
	carrierHandshakeTimeout time.Duration
	streamHandshakeTimeout  time.Duration
	maxPendingHandshakes    int
	handshakeSlotsOnce      sync.Once
	handshakeSlots          chan struct{}
	setBrutalOptions        func(net.Conn, uint64) error
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
		maxPendingHandshakes:    defaultMaxPendingHandshakes,
		setBrutalOptions:        SetBrutalOptions,
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
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConnection.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)

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
	brutal := newServerBrutalController(ctx, s.setBrutalOptions)
	if request.Protocol == protocolH2MUX {
		return s.serveH2Mux(ctx, connection, brutal)
	}
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := mplsmux.Server(connection, config)
	if err != nil {
		return err
	}

	handshakeSlots := s.pendingHandshakeSlots()
	var handlers sync.WaitGroup
	defer func() {
		_ = session.Close()
		handlers.Wait()
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
				s.handleStream(ctx, stream, handshakeSlots, brutal)
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

func (s *Service) handleStream(ctx context.Context, stream net.Conn, handshakeSlots chan struct{}, brutal *serverBrutalController) {
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
		if closeCarrier && brutal.physical != nil {
			_ = brutal.physical.Close()
		}
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
