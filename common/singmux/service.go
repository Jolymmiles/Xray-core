// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

const defaultMaxConcurrentStreams = 512

type Service struct {
	dispatcher              routing.Dispatcher
	carrierHandshakeTimeout time.Duration
	streamHandshakeTimeout  time.Duration
	maxConcurrentStreams    int
}

func NewService(dispatcher routing.Dispatcher) *Service {
	return &Service{
		dispatcher:              dispatcher,
		carrierHandshakeTimeout: handshakeTimeout,
		streamHandshakeTimeout:  handshakeTimeout,
		maxConcurrentStreams:    defaultMaxConcurrentStreams,
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
	if request.Version == carrierVersionPadded {
		connection = newPaddingConn(connection)
	}
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := mplsmux.Server(connection, config)
	if err != nil {
		return err
	}

	limit := s.maxConcurrentStreams
	if limit <= 0 {
		limit = defaultMaxConcurrentStreams
	}
	slots := make(chan struct{}, limit)
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
		case slots <- struct{}{}:
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { <-slots }()
				s.handleStream(ctx, stream)
			}()
		case <-ctx.Done():
			_ = stream.Close()
			return ctx.Err()
		case <-session.CloseChan():
			_ = stream.Close()
			return net.ErrClosed
		}
	}
}

func (s *Service) handleStream(ctx context.Context, stream net.Conn) {
	defer stream.Close()
	deadline := time.Now().Add(s.streamHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = stream.SetReadDeadline(deadline)
	flags, destination, err := readStreamRequest(stream)
	if err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	if err := writeStreamResponse(stream, nil); err != nil {
		return
	}

	var reader buf.Reader = buf.NewReader(stream)
	var writer buf.Writer = buf.NewWriter(stream)
	if flags&streamFlagUDP != 0 {
		reader = &packetReader{stream: stream}
		writer = &packetWriter{stream: stream, destination: destination}
	}
	_ = s.dispatcher.DispatchLink(ctx, destination, &transport.Link{Reader: reader, Writer: writer})
}
