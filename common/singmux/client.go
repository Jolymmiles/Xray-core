// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/transport"
)

const (
	magicDomain              = "sp.mux.sing-box.arpa"
	magicPort         X.Port = 444
	defaultMinStreams        = 8
	handshakeTimeout         = 10 * time.Second
)

type Dialer interface {
	DialContext(context.Context, X.Destination) (net.Conn, error)
}

type Options struct {
	Dialer           Dialer
	Protocol         string
	MaxConnections   int
	MinStreams       int
	MaxStreams       int
	Padding          bool
	OnlyTCP          bool
	LogicalHalfClose string
	Brutal           BrutalOptions
}

type Client struct {
	dialer           Dialer
	protocol         string
	maxConnections   int
	streamLimit      int
	padding          bool
	onlyTCP          bool
	logicalHalfClose string
	negotiationState byte
	brutal           BrutalOptions

	mu       sync.Mutex
	sessions []clientSession
	retired  []clientSession
	pending  map[clientSession]int
	closed   bool
}

type clientSession interface {
	OpenStream(context.Context, func()) (net.Conn, error)
	NumStreams() int
	IsClosed() bool
	Close() error
}

type transactionalClientSession interface {
	OpenStreamAccounted(context.Context, func(func())) (net.Conn, error)
}

type smuxClientSession struct {
	*mplsmux.Session
}

func (s *smuxClientSession) OpenStream(ctx context.Context, accounted func()) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stream, err := s.Session.OpenStream()
	if err == nil {
		accounted()
	}
	return stream, err
}

func (s *smuxClientSession) OpenStreamAccounted(ctx context.Context, accounted func(func())) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.Session.OpenStreamWithAccounting(accounted)
}

func NewClient(options Options) (*Client, error) {
	if options.Dialer == nil {
		return nil, errors.New("SMUX dialer is required")
	}
	if options.Protocol != "smux" && options.Protocol != "h2mux" {
		return nil, fmt.Errorf("unsupported mux protocol %q", options.Protocol)
	}
	policy := options.LogicalHalfClose
	if policy == "" {
		policy = "off"
	}
	if policy != "off" && policy != "auto" && policy != "require" {
		return nil, fmt.Errorf("unsupported logical half-close policy %q", policy)
	}
	if options.Protocol != "smux" && policy != "off" {
		return nil, errors.New("logical half-close is only supported by SMUX")
	}
	if options.MaxConnections < 0 || options.MinStreams < 0 || options.MaxStreams < 0 {
		return nil, errors.New("SMUX pool limits cannot be negative")
	}
	if options.MaxConnections > 0 && options.MaxStreams > 0 {
		return nil, errors.New("maxConnections and maxStreams are mutually exclusive")
	}
	if options.MinStreams > 0 && options.MaxStreams > 0 {
		return nil, errors.New("minStreams and maxStreams are mutually exclusive")
	}
	if options.Brutal.Enabled {
		if options.Brutal.SendBPS < BrutalMinSpeedBPS {
			return nil, errors.New("brutal upload speed is below the minimum")
		}
		if options.Brutal.ReceiveBPS < BrutalMinSpeedBPS {
			return nil, errors.New("brutal download speed is below the minimum")
		}
	}
	limit := options.MinStreams
	if options.MaxStreams > 0 {
		limit = options.MaxStreams
	}
	if limit == 0 {
		limit = defaultMinStreams
	}
	return &Client{
		dialer:           options.Dialer,
		protocol:         options.Protocol,
		maxConnections:   options.MaxConnections,
		streamLimit:      limit,
		padding:          options.Padding,
		onlyTCP:          options.OnlyTCP,
		logicalHalfClose: policy,
		brutal:           options.Brutal,
	}, nil
}

func IsDestination(destination X.Destination) bool {
	return destination.Network == X.Network_TCP && destination.Port == magicPort &&
		destination.Address != nil && destination.Address.Family() == X.AddressFamilyDomain &&
		destination.Address.Domain() == magicDomain
}

func (c *Client) ShouldHandle(network X.Network) bool {
	return network == X.Network_TCP || network == X.Network_UDP && !c.onlyTCP
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := append(c.sessions, c.retired...)
	c.sessions = nil
	c.retired = nil
	c.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
	return nil
}

func (c *Client) openStream(ctx context.Context) (net.Conn, error) {
	stream, _, err := c.openStreamWithOwner(ctx)
	return stream, err
}

func (c *Client) openStreamWithOwner(ctx context.Context) (net.Conn, clientSession, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, nil, net.ErrClosed
		}
		var drained []clientSession
		retired := c.retired[:0]
		for _, session := range c.retired {
			if session.NumStreams()+c.pending[session] == 0 {
				drained = append(drained, session)
			} else {
				retired = append(retired, session)
			}
		}
		c.retired = retired
		alive := c.sessions[:0]
		for _, session := range c.sessions {
			if !session.IsClosed() {
				alive = append(alive, session)
			} else if session.NumStreams()+c.pending[session] > 0 {
				c.retired = append(c.retired, session)
			} else {
				drained = append(drained, session)
			}
		}
		c.sessions = alive
		if len(drained) != 0 {
			c.mu.Unlock()
			for _, session := range drained {
				_ = session.Close()
			}
			continue
		}

		var selected clientSession
		leastStreams := int(^uint(0) >> 1)
		for _, session := range c.sessions {
			if count := session.NumStreams() + c.pending[session]; count < leastStreams {
				selected = session
				leastStreams = count
			}
		}
		canCreate := !c.brutal.Enabled && (c.maxConnections == 0 || len(c.sessions) < c.maxConnections)
		if selected == nil || leastStreams >= c.streamLimit && canCreate {
			var err error
			selected, err = c.createSession(ctx)
			if err != nil {
				c.mu.Unlock()
				return nil, nil, err
			}
			c.sessions = append(c.sessions, selected)
		}
		if c.pending == nil {
			c.pending = make(map[clientSession]int)
		}
		c.pending[selected]++
		c.mu.Unlock()
		var accounted sync.Once
		finishAccounting := func(publish func()) {
			c.mu.Lock()
			publish()
			if c.pending[selected] <= 1 {
				delete(c.pending, selected)
			} else {
				c.pending[selected]--
			}
			c.mu.Unlock()
		}
		var stream net.Conn
		var err error
		if transactional, ok := selected.(transactionalClientSession); ok {
			stream, err = transactional.OpenStreamAccounted(ctx, func(publish func()) {
				accounted.Do(func() { finishAccounting(publish) })
			})
		} else {
			stream, err = selected.OpenStream(ctx, func() {
				accounted.Do(func() { finishAccounting(func() {}) })
			})
		}
		accounted.Do(func() { finishAccounting(func() {}) })
		c.mu.Lock()
		if err == nil {
			if c.closed {
				c.mu.Unlock()
				_ = stream.Close()
				return nil, nil, net.ErrClosed
			}
			c.mu.Unlock()
			return stream, selected, nil
		}
		if ctx.Err() != nil {
			c.mu.Unlock()
			return nil, nil, ctx.Err()
		}
		removed := false
		for index, session := range c.sessions {
			if session == selected {
				c.sessions = append(c.sessions[:index], c.sessions[index+1:]...)
				removed = true
				break
			}
		}
		shouldClose := selected.NumStreams()+c.pending[selected] == 0
		if shouldClose {
			for index, session := range c.retired {
				if session == selected {
					c.retired = append(c.retired[:index], c.retired[index+1:]...)
					break
				}
			}
		} else if removed {
			c.retired = append(c.retired, selected)
		}
		c.mu.Unlock()
		if shouldClose {
			_ = selected.Close()
		}
	}
}

func (c *Client) recoveryAttempts() int {
	if c.maxConnections > 1 {
		return c.maxConnections
	}
	if c.maxConnections == 0 {
		return 4
	}
	return 1
}

func (c *Client) retireSession(failed clientSession) {
	if failed == nil {
		return
	}
	c.mu.Lock()
	removed := false
	for index, session := range c.sessions {
		if session == failed {
			c.sessions = append(c.sessions[:index], c.sessions[index+1:]...)
			removed = true
			break
		}
	}
	if !removed {
		c.mu.Unlock()
		return
	}
	shouldClose := failed.NumStreams()+c.pending[failed] == 0
	if !shouldClose {
		c.retired = append(c.retired, failed)
	}
	c.mu.Unlock()
	if shouldClose {
		_ = failed.Close()
	}
}

type carrierNegotiationError struct{ err error }

func (e *carrierNegotiationError) Error() string { return "SMUX carrier negotiation: " + e.err.Error() }
func (e *carrierNegotiationError) Unwrap() error { return e.err }

func (c *Client) createSession(ctx context.Context) (clientSession, error) {
	const (
		negotiationUnknown byte = iota
		negotiationLegacy
		negotiationEnhanced
	)
	negotiated := c.protocol == "smux" && c.logicalHalfClose != "off"
	if c.logicalHalfClose == "auto" {
		switch c.negotiationState {
		case negotiationLegacy:
			negotiated = false
		case negotiationEnhanced:
			negotiated = true
		}
	}
	session, err := c.createSessionAttempt(ctx, negotiated)
	if err == nil {
		if c.logicalHalfClose == "auto" {
			if negotiated {
				c.negotiationState = negotiationEnhanced
			} else {
				c.negotiationState = negotiationLegacy
			}
		}
		return session, nil
	}
	var negotiationErr *carrierNegotiationError
	if !negotiated || c.logicalHalfClose != "auto" || c.negotiationState == negotiationEnhanced || ctx.Err() != nil || !errors.As(err, &negotiationErr) {
		return nil, err
	}
	legacy, legacyErr := c.createSessionAttempt(ctx, false)
	if legacyErr != nil {
		return nil, errors.Join(err, legacyErr)
	}
	c.negotiationState = negotiationLegacy
	return legacy, nil
}

func (c *Client) createSessionAttempt(ctx context.Context, negotiated bool) (clientSession, error) {
	connection, err := c.dialer.DialContext(ctx, X.TCPDestination(X.DomainAddress(magicDomain), magicPort))
	if err != nil {
		return nil, err
	}
	rawConnection := connection
	completed := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = rawConnection.Close()
		case <-completed:
		}
	}()
	stopWatcher := func() {
		close(completed)
		<-watcherDone
	}
	defer stopWatcher()
	deadline := handshakeDeadline(ctx)
	_ = connection.SetDeadline(deadline)
	var carrierPadding []byte
	if c.padding {
		carrierPadding = make([]byte, 32)
		if _, err := rand.Read(carrierPadding); err != nil {
			_ = connection.Close()
			return nil, err
		}
	}
	protocol := protocolSMUX
	if c.protocol == "h2mux" {
		protocol = protocolH2MUX
	}
	if negotiated {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			_ = connection.Close()
			return nil, err
		}
		if err := writeCarrierNegotiationRequest(connection, protocol, carrierPadding, carrierFeatureLogicalHalfClose, nonce); err != nil {
			_ = connection.Close()
			return nil, &carrierNegotiationError{err: err}
		}
		response, err := readCarrierNegotiationResponse(connection, carrierFeatureLogicalHalfClose, nonce)
		if err != nil || response.Status != carrierNegotiationAccepted || response.Features&carrierFeatureLogicalHalfClose == 0 {
			_ = connection.Close()
			if err == nil {
				err = errors.New("peer rejected logical half-close")
			}
			return nil, &carrierNegotiationError{err: err}
		}
	} else if err := writeCarrierRequest(connection, protocol, carrierPadding); err != nil {
		_ = connection.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if ctx.Err() != nil {
		_ = connection.Close()
		return nil, ctx.Err()
	}
	if c.padding {
		connection = newPaddingConn(connection)
	}
	_ = connection.SetDeadline(time.Time{})
	var session clientSession
	if c.protocol == "h2mux" {
		var h2Session *h2ClientSession
		h2Session, err = newH2ClientSession(connection)
		if err == nil {
			pingContext, cancelPing := context.WithDeadline(ctx, handshakeDeadline(ctx))
			err = h2Session.client.Ping(pingContext)
			cancelPing()
			if err == nil {
				session = h2Session
			}
		}
	} else {
		config := mplsmux.DefaultConfig()
		config.KeepAliveDisabled = true
		config.LogicalHalfClose = negotiated
		mplSession, sessionErr := mplsmux.Client(connection, config)
		err = sessionErr
		if err == nil {
			session = &smuxClientSession{Session: mplSession}
		}
	}
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if c.brutal.Enabled {
		if err := c.exchangeBrutal(ctx, rawConnection, session); err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("brutal exchange: %w", err)
		}
	}
	return session, nil
}

type brutalConfigurer interface {
	SetBrutal(sendBPS uint64) error
}

func (c *Client) exchangeBrutal(ctx context.Context, carrier net.Conn, session clientSession) error {
	configurer, ok := carrier.(brutalConfigurer)
	if !ok {
		return fmt.Errorf("SMUX carrier %T cannot configure Brutal", carrier)
	}
	stream, err := session.OpenStream(ctx, func() {})
	if err != nil {
		return err
	}
	defer stream.Close()

	_ = stream.SetDeadline(handshakeDeadline(ctx))
	destination := X.TCPDestination(X.DomainAddress(brutalExchangeDomain), 0)
	if err := writeStreamRequest(stream, 0, destination); err != nil {
		return err
	}
	if err := writeBrutalRequest(stream, c.brutal.ReceiveBPS); err != nil {
		return err
	}
	if err := readStreamResponse(stream); err != nil {
		return err
	}
	peerReceiveBPS, err := readBrutalResponse(stream)
	if err != nil {
		return err
	}
	sendBPS := min(c.brutal.SendBPS, peerReceiveBPS)
	return configurer.SetBrutal(sendBPS)
}

func handshakeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(handshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func prepareTargetStream(ctx context.Context, stream net.Conn, destination X.Destination) (net.Conn, error) {
	_ = stream.SetWriteDeadline(handshakeDeadline(ctx))
	flags := uint16(0)
	if destination.Network == X.Network_UDP {
		flags = streamFlagUDP | streamFlagPacketAddr
	}
	if err := writeStreamRequest(stream, flags, destination); err != nil {
		_ = stream.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Time{})
	return stream, nil
}

func (c *Client) openTargetStreamWithOwner(ctx context.Context, destination X.Destination) (net.Conn, clientSession, error) {
	stream, owner, err := c.openStreamWithOwner(ctx)
	if err != nil {
		return nil, nil, err
	}
	stream, err = prepareTargetStream(ctx, stream, destination)
	if err != nil {
		return nil, nil, err
	}
	return stream, owner, nil
}

func (c *Client) openTargetStream(ctx context.Context, destination X.Destination) (net.Conn, error) {
	stream, _, err := c.openTargetStreamWithOwner(ctx, destination)
	return stream, err
}

func closeClientLinkWriter(writer buf.Writer) error {
	if bytesWriter, ok := writer.(*buf.BufferToBytesWriter); ok {
		return common.Close(bytesWriter.Writer)
	}
	return common.Close(writer)
}

func (c *Client) Dispatch(ctx context.Context, link *transport.Link, destination X.Destination) error {
	if !c.ShouldHandle(destination.Network) {
		return errors.New("SMUX client does not handle this network")
	}
	initial, owner, err := c.openTargetStreamWithOwner(ctx, destination)
	if err != nil {
		return err
	}
	var ownerMu sync.Mutex
	connection := newBoundedRetryConn(ctx, initial, func(openCtx context.Context) (net.Conn, error) {
		ownerMu.Lock()
		failed := owner
		ownerMu.Unlock()
		c.retireSession(failed)
		stream, next, openErr := c.openTargetStreamWithOwner(openCtx, destination)
		if openErr != nil {
			return nil, openErr
		}
		ownerMu.Lock()
		owner = next
		ownerMu.Unlock()
		return stream, nil
	}, c.recoveryAttempts())
	defer connection.Close()

	var remoteReader buf.Reader = buf.NewReader(connection)
	var remoteWriter buf.Writer = buf.NewWriter(connection)
	if destination.Network == X.Network_UDP {
		remoteWriter = &packetWriter{stream: connection, destination: destination}
		remoteReader = &packetReader{stream: connection}
	}
	if destination.Network != X.Network_TCP || !connection.SupportsHalfClose() {
		results := make(chan error, 2)
		go func() { results <- buf.Copy(link.Reader, remoteWriter) }()
		go func() { results <- buf.Copy(remoteReader, link.Writer) }()
		select {
		case <-ctx.Done():
			_ = connection.Close()
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			return ctx.Err()
		case copyErr := <-results:
			_ = connection.Close()
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(copyErr, io.EOF) {
				return nil
			}
			return copyErr
		}
	}
	defer common.Interrupt(link.Reader)
	defer common.Interrupt(link.Writer)
	type copyResult struct {
		upload bool
		err    error
	}
	results := make(chan copyResult, 2)
	go func() { results <- copyResult{upload: true, err: buf.Copy(link.Reader, remoteWriter)} }()
	go func() { results <- copyResult{err: buf.Copy(remoteReader, link.Writer)} }()
	for completed := 0; completed < 2; completed++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-results:
			if result.err != nil && !errors.Is(result.err, io.EOF) {
				return result.err
			}
			if result.upload {
				if err := connection.CloseWrite(); err != nil {
					return err
				}
			} else if err := closeClientLinkWriter(link.Writer); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				return err
			}
		}
	}
	return nil
}
