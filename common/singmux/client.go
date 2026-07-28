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
	// idleSweepInterval matches the carrier monitor in common/mux: a carrier is
	// only retired once it has stayed idle across a full interval, so a pool
	// serving steady traffic keeps reusing warm carriers.
	idleSweepInterval = 16 * time.Second
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
}

// pooledSession is one carrier plus the bookkeeping the idle sweeper needs to
// tell a carrier that went quiet from one that is still serving traffic.
type pooledSession struct {
	session *mplsmux.Session
	opened  uint64 // streams handed out over this carrier's lifetime
	swept   uint64 // opened as observed by the previous sweep
	idle    bool   // carried nothing during the previous sweep interval
}

type Client struct {
	dialer         Dialer
	maxConnections int
	streamLimit    int
	padding        bool
	onlyTCP        bool
	sweepInterval  time.Duration

	mu       sync.Mutex
	sessions []*pooledSession
	closed   bool
	// sweeper stops the idle sweeper goroutine. It is nil while no carrier is
	// pooled, so an idle client holds no goroutine at all.
	sweeper chan struct{}
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
		sweepInterval:  idleSweepInterval,
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
	if c.sweeper != nil {
		close(c.sweeper)
		c.sweeper = nil
	}
	sessions := c.sessions
	c.sessions = nil
	c.mu.Unlock()
	for _, pooled := range sessions {
		_ = pooled.session.Close()
	}
	return nil
}

// retainLocked rebuilds the pool from the entries the caller kept and clears
// the vacated tail, so dropped carriers are not pinned by the backing array.
func (c *Client) retainLocked(kept []*pooledSession) {
	for index := len(kept); index < len(c.sessions); index++ {
		c.sessions[index] = nil
	}
	c.sessions = kept
}

// startSweeperLocked launches the idle sweeper on demand. Starting it with the
// first carrier keeps a client that never dials free of goroutines.
func (c *Client) startSweeperLocked() {
	if c.sweeper != nil {
		return
	}
	interval := c.sweepInterval
	if interval <= 0 {
		// A Client built without NewClient still has to reap its carriers.
		interval = idleSweepInterval
	}
	sweeper := make(chan struct{})
	c.sweeper = sweeper
	go c.sweepLoop(sweeper, interval)
}

func (c *Client) sweepLoop(sweeper chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			expired, drained := c.sweepIdle(sweeper)
			for _, session := range expired {
				_ = session.Close()
			}
			if drained {
				return
			}
		case <-sweeper:
			return
		}
	}
}

// sweepIdle retires carriers that served no stream across a full sweep
// interval, returning them for the caller to close outside the lock. A carrier
// must look idle on two consecutive sweeps before it is retired, mirroring the
// two-tick check in common/mux, so a carrier that is about to serve a request
// is never torn down. The sweep after the last stream closes only records the
// baseline, so a carrier is retired about three intervals after it goes quiet;
// that lag is deliberate, not an off-by-one. It reports whether the pool
// drained, which retires the sweeper itself.
func (c *Client) sweepIdle(sweeper chan struct{}) ([]*mplsmux.Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expired []*mplsmux.Session
	kept := c.sessions[:0]
	for _, pooled := range c.sessions {
		if pooled.session.IsClosed() {
			continue
		}
		// A carrier counts as idle only when it holds no stream now and handed
		// out none since the previous sweep; a stream opened and closed inside
		// one interval must not read as idle.
		idle := pooled.session.NumStreams() == 0 && pooled.opened == pooled.swept
		if idle && pooled.idle {
			expired = append(expired, pooled.session)
			continue
		}
		pooled.idle = idle
		pooled.swept = pooled.opened
		kept = append(kept, pooled)
	}
	c.retainLocked(kept)

	if len(c.sessions) == 0 && c.sweeper == sweeper {
		// Nothing left to watch: retire rather than tick for the lifetime of
		// the client. The next carrier starts a fresh sweeper.
		c.sweeper = nil
		return expired, true
	}
	return expired, false
}

func (c *Client) openStream(ctx context.Context) (net.Conn, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		alive := c.sessions[:0]
		for _, pooled := range c.sessions {
			if !pooled.session.IsClosed() {
				alive = append(alive, pooled)
			}
		}
		c.retainLocked(alive)

		var selected *pooledSession
		leastStreams := int(^uint(0) >> 1)
		for _, pooled := range c.sessions {
			if count := pooled.session.NumStreams(); count < leastStreams {
				selected = pooled
				leastStreams = count
			}
		}
		canCreate := c.maxConnections == 0 || len(c.sessions) < c.maxConnections
		if selected == nil || leastStreams >= c.streamLimit && canCreate {
			session, err := c.createSession(ctx)
			if err != nil {
				c.mu.Unlock()
				return nil, err
			}
			selected = &pooledSession{session: session}
			c.sessions = append(c.sessions, selected)
			c.startSweeperLocked()
		}
		stream, err := selected.session.OpenStream()
		if err == nil {
			// Record the handout so a carrier that served this interval is not
			// mistaken for an idle one by the next sweep.
			selected.opened++
			c.mu.Unlock()
			return stream, nil
		}
		for index, pooled := range c.sessions {
			if pooled == selected {
				c.retainLocked(append(c.sessions[:index], c.sessions[index+1:]...))
				break
			}
		}
		c.mu.Unlock()
		_ = selected.session.Close()
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
	deadline := handshakeDeadline(ctx)
	_ = connection.SetDeadline(deadline)
	var carrierPadding []byte
	if c.padding {
		carrierPadding = make([]byte, 32)
		if _, err := rand.Read(carrierPadding); err != nil {
			stopWatcher()
			_ = connection.Close()
			return nil, err
		}
	}
	if err := writeCarrierRequest(connection, protocolSMUX, carrierPadding); err != nil {
		stopWatcher()
		_ = connection.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	stopWatcher()
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
	return session, nil
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
