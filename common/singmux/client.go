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
	Dialer         Dialer
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
	OnlyTCP        bool
	Brutal         BrutalOptions
}

type Client struct {
	dialer         Dialer
	maxConnections int
	streamLimit    int
	padding        bool
	onlyTCP        bool
	brutal         BrutalOptions

	mu       sync.Mutex
	sessions []*mplsmux.Session
	closed   bool
}

func NewClient(options Options) (*Client, error) {
	if options.Dialer == nil {
		return nil, errors.New("SMUX dialer is required")
	}
	if options.Protocol != "smux" {
		return nil, fmt.Errorf("unsupported mux protocol %q", options.Protocol)
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
		dialer:         options.Dialer,
		maxConnections: options.MaxConnections,
		streamLimit:    limit,
		padding:        options.Padding,
		onlyTCP:        options.OnlyTCP,
		brutal:         options.Brutal,
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
	sessions := c.sessions
	c.sessions = nil
	c.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
	return nil
}

func (c *Client) openStream(ctx context.Context) (net.Conn, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		alive := c.sessions[:0]
		for _, session := range c.sessions {
			if !session.IsClosed() {
				alive = append(alive, session)
			}
		}
		c.sessions = alive

		var selected *mplsmux.Session
		leastStreams := int(^uint(0) >> 1)
		for _, session := range c.sessions {
			if count := session.NumStreams(); count < leastStreams {
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
				return nil, err
			}
			c.sessions = append(c.sessions, selected)
		}
		stream, err := selected.OpenStream()
		if err == nil {
			c.mu.Unlock()
			return stream, nil
		}
		for index, session := range c.sessions {
			if session == selected {
				c.sessions = append(c.sessions[:index], c.sessions[index+1:]...)
				break
			}
		}
		c.mu.Unlock()
		_ = selected.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
}

func (c *Client) createSession(ctx context.Context) (*mplsmux.Session, error) {
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
	if err := writeCarrierRequest(connection, protocolSMUX, carrierPadding); err != nil {
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
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := mplsmux.Client(connection, config)
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

func (c *Client) exchangeBrutal(ctx context.Context, carrier net.Conn, session *mplsmux.Session) error {
	configurer, ok := carrier.(brutalConfigurer)
	if !ok {
		return fmt.Errorf("SMUX carrier %T cannot configure Brutal", carrier)
	}
	stream, err := session.OpenStream()
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

func (c *Client) openTargetStream(ctx context.Context, destination X.Destination) (net.Conn, error) {
	stream, err := c.openStream(ctx)
	if err != nil {
		return nil, err
	}
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

func (c *Client) Dispatch(ctx context.Context, link *transport.Link, destination X.Destination) error {
	if !c.ShouldHandle(destination.Network) {
		return errors.New("SMUX client does not handle this network")
	}
	initial, err := c.openTargetStream(ctx, destination)
	if err != nil {
		return err
	}
	connection := newRetryConn(ctx, initial, func(openCtx context.Context) (net.Conn, error) {
		return c.openTargetStream(openCtx, destination)
	})
	defer connection.Close()

	var remoteReader buf.Reader = buf.NewReader(connection)
	var remoteWriter buf.Writer = buf.NewWriter(connection)
	if destination.Network == X.Network_UDP {
		remoteWriter = &packetWriter{stream: connection, destination: destination}
		remoteReader = &packetReader{stream: connection}
	}
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
