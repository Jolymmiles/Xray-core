package singmux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type echoDispatcher struct {
	target chan X.Destination
}

type wrappedDomainAddress struct {
	domain string
}

func (*wrappedDomainAddress) IP() net.IP              { return nil }
func (a *wrappedDomainAddress) Domain() string        { return a.domain }
func (*wrappedDomainAddress) Family() X.AddressFamily { return X.AddressFamilyDomain }
func (a *wrappedDomainAddress) String() string        { return a.domain }

func (*echoDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, io.ErrClosedPipe
}

func (d *echoDispatcher) DispatchLink(_ context.Context, destination X.Destination, link *transport.Link) error {
	d.target <- destination
	for {
		buffers, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		if err := link.Writer.WriteMultiBuffer(buffers); err != nil {
			return err
		}
	}
}

func (*echoDispatcher) Start() error      { return nil }
func (*echoDispatcher) Close() error      { return nil }
func (*echoDispatcher) Type() interface{} { return routing.DispatcherType() }

type serviceDialer struct {
	service *Service
}

func (d *serviceDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	go func() {
		_ = d.service.NewConnection(context.Background(), serverConn)
	}()
	return clientConn, nil
}

type countingServiceDialer struct {
	service *Service
	dials   atomic.Int32
}

type staleHandshakeDialer struct {
	service          *Service
	bytesBeforeClose int64
	dials            atomic.Int32
}

type resetAfterHandshakeSession struct{}

type resetAfterHandshakeConn struct {
	writes atomic.Int32
}

func (*resetAfterHandshakeSession) OpenStream(context.Context, func()) (net.Conn, error) {
	return new(resetAfterHandshakeConn), nil
}
func (*resetAfterHandshakeSession) NumStreams() int { return 0 }
func (*resetAfterHandshakeSession) IsClosed() bool  { return false }
func (*resetAfterHandshakeSession) Close() error    { return nil }

func (*resetAfterHandshakeConn) Read([]byte) (int, error) { return 0, syscall.ECONNRESET }
func (c *resetAfterHandshakeConn) Write(payload []byte) (int, error) {
	if c.writes.Add(1) <= 2 {
		return len(payload), nil
	}
	return 0, syscall.ECONNRESET
}
func (*resetAfterHandshakeConn) Close() error                     { return nil }
func (*resetAfterHandshakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*resetAfterHandshakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*resetAfterHandshakeConn) SetDeadline(time.Time) error      { return nil }
func (*resetAfterHandshakeConn) SetReadDeadline(time.Time) error  { return nil }
func (*resetAfterHandshakeConn) SetWriteDeadline(time.Time) error { return nil }

type blockedHandshakeDialer struct{}

type errorDialer struct{ err error }

func (d *errorDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	return nil, d.err
}

type failedOpenSession struct {
	active     int
	closed     bool
	openErr    error
	closeCalls atomic.Int32
}

func (s *failedOpenSession) OpenStream(context.Context, func()) (net.Conn, error) {
	return nil, s.openErr
}
func (s *failedOpenSession) NumStreams() int { return s.active }
func (s *failedOpenSession) IsClosed() bool  { return s.closed }
func (s *failedOpenSession) Close() error {
	s.closeCalls.Add(1)
	return nil
}

type blockingOpenSession struct {
	started       chan struct{}
	active        atomic.Int32
	reflectOnOpen bool
}

func (s *blockingOpenSession) OpenStream(ctx context.Context, accounted func()) (net.Conn, error) {
	if s.reflectOnOpen {
		s.active.Store(1)
		accounted()
	}
	s.started <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (s *blockingOpenSession) NumStreams() int { return int(s.active.Load()) }
func (*blockingOpenSession) IsClosed() bool    { return false }
func (*blockingOpenSession) Close() error      { return nil }

type accountingProbeSession struct {
	client    *Client
	active    atomic.Int32
	published chan error
}

func (s *accountingProbeSession) OpenStream(context.Context, func()) (net.Conn, error) {
	return nil, errors.New("non-transactional open used")
}

func (s *accountingProbeSession) OpenStreamAccounted(ctx context.Context, accounted func(func())) (net.Conn, error) {
	accounted(func() {
		if pending := s.client.pending[s]; pending != 1 {
			s.published <- fmt.Errorf("pending during publication = %d, want 1", pending)
			return
		}
		s.active.Store(1)
		s.published <- nil
	})
	<-ctx.Done()
	return nil, ctx.Err()
}
func (s *accountingProbeSession) NumStreams() int { return int(s.active.Load()) }
func (*accountingProbeSession) IsClosed() bool    { return false }
func (*accountingProbeSession) Close() error      { return nil }

type closingOpenSession struct {
	started chan struct{}
	release chan struct{}
	stream  net.Conn
}

func (s *closingOpenSession) OpenStream(context.Context, func()) (net.Conn, error) {
	close(s.started)
	<-s.release
	return s.stream, nil
}
func (*closingOpenSession) NumStreams() int { return 0 }
func (*closingOpenSession) IsClosed() bool  { return false }
func (*closingOpenSession) Close() error    { return nil }

type brutalCarrierConn struct {
	net.Conn
	applied chan uint64
	err     error
}

func (c *brutalCarrierConn) SetBrutal(sendBPS uint64) error {
	if c.err != nil {
		return c.err
	}
	c.applied <- sendBPS
	return nil
}

type brutalTestDialer struct {
	serverReceiveBPS uint64
	dials            atomic.Int32
	clientReceiveBPS chan uint64
	applied          chan uint64
	serverError      chan error
}

type blockedBrutalDialer struct {
	requestRead chan struct{}
	clientConn  chan net.Conn
	release     chan struct{}
	releaseOnce atomic.Bool
}

func (d *brutalTestDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	d.dials.Add(1)
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		if _, err := readCarrierRequest(serverConn); err != nil {
			d.serverError <- err
			return
		}
		config := localsmux.DefaultConfig()
		config.KeepAliveDisabled = true
		session, err := localsmux.Server(serverConn, config)
		if err != nil {
			d.serverError <- err
			return
		}
		defer session.Close()
		stream, err := session.AcceptStream()
		if err != nil {
			d.serverError <- err
			return
		}
		flags, destination, err := readStreamRequest(stream)
		if err != nil {
			d.serverError <- err
			return
		}
		if flags != 0 || destination.Network != X.Network_TCP || destination.Port != 0 || destination.Address.Domain() != brutalExchangeDomain {
			d.serverError <- errors.New("unexpected brutal exchange destination")
			return
		}
		receiveBPS, err := readBrutalRequest(stream)
		if err != nil {
			d.serverError <- err
			return
		}
		d.clientReceiveBPS <- receiveBPS
		if err := writeStreamResponse(stream, nil); err != nil {
			d.serverError <- err
			return
		}
		if err := writeBrutalResponse(stream, d.serverReceiveBPS, true, ""); err != nil {
			d.serverError <- err
			return
		}
		_ = stream.Close()
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			defer stream.Close()
		}
	}()
	return &brutalCarrierConn{Conn: clientConn, applied: d.applied}, nil
}

func (d *blockedBrutalDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	d.clientConn <- clientConn
	go func() {
		defer serverConn.Close()
		if _, err := readCarrierRequest(serverConn); err != nil {
			return
		}
		config := localsmux.DefaultConfig()
		config.KeepAliveDisabled = true
		session, err := localsmux.Server(serverConn, config)
		if err != nil {
			return
		}
		defer session.Close()
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		if _, _, err := readStreamRequest(stream); err != nil {
			return
		}
		if _, err := readBrutalRequest(stream); err != nil {
			return
		}
		close(d.requestRead)
		<-d.release
	}()
	return &brutalCarrierConn{Conn: clientConn}, nil
}

func (d *blockedBrutalDialer) unblock() {
	if d.releaseOnce.CompareAndSwap(false, true) {
		close(d.release)
	}
}

func (*blockedHandshakeDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		if _, err := readCarrierRequest(serverConn); err != nil {
			return
		}
		config := localsmux.DefaultConfig()
		config.KeepAliveDisabled = true
		session, err := localsmux.Server(serverConn, config)
		if err != nil {
			return
		}
		defer session.Close()
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		if _, _, err := readStreamRequest(stream); err != nil {
			return
		}
		<-session.CloseChan()
	}()
	return clientConn, nil
}

func (d *staleHandshakeDialer) DialContext(ctx context.Context, destination X.Destination) (net.Conn, error) {
	if d.dials.Add(1) != 1 {
		return (&serviceDialer{service: d.service}).DialContext(ctx, destination)
	}
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		if _, err := readCarrierRequest(serverConn); err != nil {
			return
		}
		config := localsmux.DefaultConfig()
		config.KeepAliveDisabled = true
		session, err := localsmux.Server(serverConn, config)
		if err != nil {
			return
		}
		defer session.Close()
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		if _, _, err := readStreamRequest(stream); err != nil {
			return
		}
		if d.bytesBeforeClose > 0 {
			_, _ = io.CopyN(io.Discard, stream, d.bytesBeforeClose)
		}
	}()
	return clientConn, nil
}

func (d *countingServiceDialer) DialContext(ctx context.Context, destination X.Destination) (net.Conn, error) {
	d.dials.Add(1)
	return (&serviceDialer{service: d.service}).DialContext(ctx, destination)
}

func linkPair() (*transport.Link, *transport.Link) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: uplinkReader, Writer: downlinkWriter},
		&transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
}

func TestClientDispatchTCP(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	client, err := NewClient(Options{
		Dialer:         &serviceDialer{service: NewService(dispatcher)},
		Protocol:       "smux",
		MaxConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	clientLink, peerLink := linkPair()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- client.Dispatch(ctx, clientLink, destination) }()

	common.Must(peerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}))
	response, err := peerLink.Reader.ReadMultiBuffer()
	common.Must(err)
	defer buf.ReleaseMulti(response)
	if got := response.String(); got != "hello" {
		t.Fatalf("response = %q, want hello", got)
	}
	select {
	case target := <-dispatcher.target:
		if target != destination {
			t.Fatalf("target = %s, want %s", target, destination)
		}
	case <-ctx.Done():
		t.Fatal("server did not receive target")
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not stop after cancellation")
	}
}

func TestClientRetriesStaleCarrierWithBufferedTCPPayload(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	dialer := &staleHandshakeDialer{service: NewService(dispatcher), bytesBeforeClose: 512 * 1024}
	client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	clientLink, peerLink := linkPair()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- client.Dispatch(ctx, clientLink, destination) }()

	payload := make([]byte, 1024*1024)
	for index := range payload {
		payload[index] = byte(index)
	}
	if err := peerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		payload []byte
		err     error
	}
	responseCh := make(chan readResult, 1)
	go func() {
		var response bytes.Buffer
		for response.Len() < len(payload) {
			buffers, err := peerLink.Reader.ReadMultiBuffer()
			if err != nil {
				responseCh <- readResult{err: err}
				return
			}
			for _, buffer := range buffers {
				_, _ = response.Write(buffer.Bytes())
			}
			buf.ReleaseMulti(buffers)
		}
		responseCh <- readResult{payload: response.Bytes()}
	}()
	var response []byte
	select {
	case result := <-responseCh:
		if result.err != nil {
			select {
			case dispatchErr := <-errCh:
				t.Fatalf("read after stale carrier retry: %v (dispatch: %v)", result.err, dispatchErr)
			case <-time.After(100 * time.Millisecond):
				t.Fatalf("read after stale carrier retry: %v (dispatch still running)", result.err)
			}
		}
		response = result.payload
	case dispatchErr := <-errCh:
		t.Fatalf("dispatch failed instead of retrying stale carrier: %v", dispatchErr)
	case <-ctx.Done():
		t.Fatal("stale carrier retry timed out")
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("response length = %d, want %d", len(response), len(payload))
	}
	if got := dialer.dials.Load(); got != 2 {
		t.Fatalf("carrier dials = %d, want 2", got)
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not stop after cancellation")
	}
}

func TestClientRetrySkipsResetCarrierForHealthyPooledSibling(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	dialer := &countingServiceDialer{service: NewService(dispatcher)}
	client := &Client{
		dialer:           dialer,
		protocol:         "smux",
		logicalHalfClose: "off",
		maxConnections:   4,
		streamLimit:      defaultMinStreams,
	}
	healthy, err := client.createSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	client.sessions = []clientSession{new(resetAfterHandshakeSession), healthy}
	defer client.Close()

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	clientLink, peerLink := linkPair()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dispatchResult := make(chan error, 1)
	go func() { dispatchResult <- client.Dispatch(ctx, clientLink, destination) }()

	if err := peerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		buffers buf.MultiBuffer
		err     error
	}
	response := make(chan readResult, 1)
	go func() {
		buffers, err := peerLink.Reader.ReadMultiBuffer()
		response <- readResult{buffers: buffers, err: err}
	}()
	select {
	case result := <-response:
		if result.err != nil {
			t.Fatalf("read after pooled stale carrier reset: %v", result.err)
		}
		defer buf.ReleaseMulti(result.buffers)
		if got := result.buffers.String(); got != "hello" {
			t.Fatalf("response = %q, want hello", got)
		}
	case err := <-dispatchResult:
		t.Fatalf("dispatch failed instead of reusing the healthy pooled carrier: %v", err)
	case <-ctx.Done():
		t.Fatal("healthy pooled carrier recovery timed out")
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("carrier dials = %d, want the one preloaded healthy carrier", got)
	}
	cancel()
	select {
	case <-dispatchResult:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not stop after cancellation")
	}
}

func TestClientRetryEvictsEveryDeadSiblingThenDials(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	dialer := &countingServiceDialer{service: NewService(dispatcher)}
	client := &Client{
		dialer:           dialer,
		protocol:         "smux",
		logicalHalfClose: "off",
		maxConnections:   4,
		streamLimit:      defaultMinStreams,
	}
	client.sessions = []clientSession{new(resetAfterHandshakeSession), new(resetAfterHandshakeSession)}
	defer client.Close()

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	clientLink, peerLink := linkPair()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dispatchResult := make(chan error, 1)
	go func() { dispatchResult <- client.Dispatch(ctx, clientLink, destination) }()

	if err := peerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		buffers buf.MultiBuffer
		err     error
	}
	response := make(chan readResult, 1)
	go func() {
		buffers, err := peerLink.Reader.ReadMultiBuffer()
		response <- readResult{buffers: buffers, err: err}
	}()
	select {
	case result := <-response:
		if result.err != nil {
			t.Fatalf("read after evicting every dead sibling: %v", result.err)
		}
		defer buf.ReleaseMulti(result.buffers)
		if got := result.buffers.String(); got != "hello" {
			t.Fatalf("response = %q, want hello", got)
		}
	case err := <-dispatchResult:
		t.Fatalf("dispatch failed instead of dialing after dead siblings: %v", err)
	case <-ctx.Done():
		t.Fatal("dead-sibling recovery timed out")
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("carrier dials = %d, want 1 new carrier after both siblings reset", got)
	}
	cancel()
	select {
	case <-dispatchResult:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not stop after cancellation")
	}
}

func TestClientStreamHandshakeHonorsContextCancellation(t *testing.T) {
	client, err := NewClient(Options{Dialer: &blockedHandshakeDialer{}, Protocol: "smux", MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientLink, _ := linkPair()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Dispatch(ctx, clientLink, X.TCPDestination(X.DomainAddress("example.com"), 443))
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dispatch error = %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stream handshake ignored context cancellation")
	}
}

func TestClientDispatchUDPPerPacketDestination(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	client, err := NewClient(Options{
		Dialer:         &serviceDialer{service: NewService(dispatcher)},
		Protocol:       "smux",
		MaxConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	defaultDestination := X.UDPDestination(X.DomainAddress("default.example"), 53)
	packetDestination := X.UDPDestination(X.DomainAddress("packet.example"), 5353)
	clientLink, peerLink := linkPair()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- client.Dispatch(ctx, clientLink, defaultDestination) }()

	packet := buf.FromBytes([]byte("query"))
	packet.UDP = &packetDestination
	common.Must(peerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}))
	response, err := peerLink.Reader.ReadMultiBuffer()
	common.Must(err)
	defer buf.ReleaseMulti(response)
	if got := response.String(); got != "query" {
		t.Fatalf("response = %q, want query", got)
	}
	if len(response) != 1 || response[0].UDP == nil || *response[0].UDP != packetDestination {
		t.Fatalf("response destination = %#v, want %s", response[0].UDP, packetDestination)
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not stop after cancellation")
	}
}

func TestClientOnlyTCPSelection(t *testing.T) {
	client := &Client{onlyTCP: true}
	if !client.ShouldHandle(X.Network_TCP) || client.ShouldHandle(X.Network_UDP) {
		t.Fatal("onlyTcp must select TCP and bypass UDP")
	}
}

func TestNewClientSupportsH2MUX(t *testing.T) {
	if _, err := NewClient(Options{Dialer: &serviceDialer{}, Protocol: "h2mux"}); err != nil {
		t.Fatalf("h2mux must be accepted: %v", err)
	}
	for _, protocol := range []string{"yamux", "unknown"} {
		if _, err := NewClient(Options{Dialer: &serviceDialer{}, Protocol: protocol}); err == nil {
			t.Fatalf("protocol %q must be rejected", protocol)
		}
	}
}

func TestNewClientRejectsConflictingPoolModes(t *testing.T) {
	_, err := NewClient(Options{
		Dialer:         &serviceDialer{},
		Protocol:       "smux",
		MaxConnections: 2,
		MaxStreams:     8,
	})
	if err == nil {
		t.Fatal("maxConnections and maxStreams must not be combined")
	}
}

func TestNewClientValidatesRequiredDialerAndLimits(t *testing.T) {
	if _, err := NewClient(Options{Protocol: "smux"}); err == nil {
		t.Fatal("missing dialer must be rejected")
	}
	if _, err := NewClient(Options{Dialer: &serviceDialer{}, Protocol: "smux", MinStreams: -1}); err == nil {
		t.Fatal("negative pool limit must be rejected")
	}
	if _, err := NewClient(Options{Dialer: &serviceDialer{}, Protocol: "smux", MinStreams: 1, MaxStreams: 2}); err == nil {
		t.Fatal("minStreams and maxStreams must not be combined")
	}
	if _, err := NewClient(Options{
		Dialer:   &serviceDialer{},
		Protocol: "smux",
		Brutal:   BrutalOptions{Enabled: true, SendBPS: BrutalMinSpeedBPS - 1, ReceiveBPS: BrutalMinSpeedBPS},
	}); err == nil {
		t.Fatal("brutal upload below the minimum must be rejected")
	}
	if _, err := NewClient(Options{
		Dialer:   &serviceDialer{},
		Protocol: "smux",
		Brutal:   BrutalOptions{Enabled: true, SendBPS: BrutalMinSpeedBPS, ReceiveBPS: BrutalMinSpeedBPS - 1},
	}); err == nil {
		t.Fatal("brutal download below the minimum must be rejected")
	}
}

func TestClientBrutalNegotiatesAndReusesSingleCarrier(t *testing.T) {
	const (
		clientSendBPS    = 12_500_000
		clientReceiveBPS = 25_000_000
		serverReceiveBPS = 6_250_000
	)
	dialer := &brutalTestDialer{
		serverReceiveBPS: serverReceiveBPS,
		clientReceiveBPS: make(chan uint64, 1),
		applied:          make(chan uint64, 1),
		serverError:      make(chan error, 1),
	}
	client, err := NewClient(Options{
		Dialer:     dialer,
		Protocol:   "smux",
		MaxStreams: 1,
		Brutal: BrutalOptions{
			Enabled:    true,
			SendBPS:    clientSendBPS,
			ReceiveBPS: clientReceiveBPS,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	streams := make([]net.Conn, 0, 3)
	for range 3 {
		stream, err := client.openStream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, stream)
	}
	for _, stream := range streams {
		defer stream.Close()
	}

	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("carrier dials = %d, want 1", got)
	}
	select {
	case got := <-dialer.clientReceiveBPS:
		if got != clientReceiveBPS {
			t.Fatalf("advertised receive BPS = %d, want %d", got, clientReceiveBPS)
		}
	case err := <-dialer.serverError:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("brutal request was not received")
	}
	select {
	case got := <-dialer.applied:
		if got != serverReceiveBPS {
			t.Fatalf("applied send BPS = %d, want negotiated %d", got, serverReceiveBPS)
		}
	case <-time.After(time.Second):
		t.Fatal("negotiated brutal rate was not applied")
	}
}

func TestClientBrutalCancellationClosesExchange(t *testing.T) {
	dialer := &blockedBrutalDialer{
		requestRead: make(chan struct{}),
		clientConn:  make(chan net.Conn, 1),
		release:     make(chan struct{}),
	}
	client, err := NewClient(Options{
		Dialer:   dialer,
		Protocol: "smux",
		Brutal: BrutalOptions{
			Enabled:    true,
			SendBPS:    BrutalMinSpeedBPS,
			ReceiveBPS: BrutalMinSpeedBPS,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer dialer.unblock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		stream, err := client.openStream(ctx)
		if stream != nil {
			_ = stream.Close()
		}
		result <- err
	}()

	var carrier net.Conn
	select {
	case carrier = <-dialer.clientConn:
	case <-time.After(time.Second):
		t.Fatal("brutal carrier was not dialed")
	}
	select {
	case <-dialer.requestRead:
	case <-time.After(time.Second):
		t.Fatal("brutal request was not read")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled brutal exchange unexpectedly succeeded")
		}
	case <-time.After(250 * time.Millisecond):
		_ = carrier.Close()
		dialer.unblock()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("brutal exchange remained blocked after carrier close")
		}
		t.Fatal("cancellation did not close brutal exchange")
	}
}

func TestNilClientClose(t *testing.T) {
	var client *Client
	common.Must(client.Close())
}

func TestClientPoolHonorsStreamThresholds(t *testing.T) {
	tests := []struct {
		name         string
		options      Options
		streams      int
		wantCarriers int32
	}{
		{name: "default min streams", streams: 9, wantCarriers: 2},
		{name: "bounded carriers", options: Options{MaxConnections: 2, MinStreams: 2}, streams: 5, wantCarriers: 2},
		{name: "max streams", options: Options{MaxStreams: 2}, streams: 5, wantCarriers: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dispatcher := &echoDispatcher{target: make(chan X.Destination, test.streams)}
			dialer := &countingServiceDialer{service: NewService(dispatcher)}
			options := test.options
			options.Dialer = dialer
			options.Protocol = "smux"
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			streams := make([]net.Conn, 0, test.streams)
			for range test.streams {
				stream, err := client.openStream(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				streams = append(streams, stream)
			}
			for _, stream := range streams {
				_ = stream.Close()
			}
			if got := dialer.dials.Load(); got != test.wantCarriers {
				t.Fatalf("carrier dials = %d, want %d", got, test.wantCarriers)
			}
		})
	}
}

func TestClientCloseIsTerminal(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	dialer := &countingServiceDialer{service: NewService(dispatcher)}
	client, err := NewClient(Options{Dialer: dialer, Protocol: "smux"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.openStream(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("open after Close error = %v, want net.ErrClosed", err)
	}
	if got := dialer.dials.Load(); got != 0 {
		t.Fatalf("closed client opened %d carriers", got)
	}
}

func TestClientCloseRejectsConcurrentOpen(t *testing.T) {
	stream, peer := net.Pipe()
	defer peer.Close()
	session := &closingOpenSession{
		started: make(chan struct{}),
		release: make(chan struct{}),
		stream:  stream,
	}
	client := &Client{
		streamLimit: defaultMinStreams,
		sessions:    []clientSession{session},
	}
	result := make(chan error, 1)
	go func() {
		opened, err := client.openStream(context.Background())
		if opened != nil {
			_ = opened.Close()
		}
		result <- err
	}()
	<-session.started
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	close(session.release)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("concurrent open error = %v, want %v", err, net.ErrClosed)
	}
}

func TestClientOpenFailureDoesNotCloseSessionWithActiveStreams(t *testing.T) {
	openErr := errors.New("graceful GOAWAY")
	replacementErr := errors.New("replacement dial failed")
	session := &failedOpenSession{active: 1, openErr: openErr}
	client := &Client{
		dialer:         &errorDialer{err: replacementErr},
		protocol:       "smux",
		maxConnections: 1,
		streamLimit:    defaultMinStreams,
		sessions:       []clientSession{session},
	}
	if _, err := client.openStream(context.Background()); !errors.Is(err, replacementErr) {
		t.Fatalf("openStream error = %v, want %v", err, replacementErr)
	}
	if got := session.closeCalls.Load(); got != 0 {
		t.Fatalf("active draining session was closed %d times", got)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if got := session.closeCalls.Load(); got != 1 {
		t.Fatalf("Client.Close closed draining session %d times, want 1", got)
	}
}

func TestClientConcurrentOpensAccountForPendingSessions(t *testing.T) {
	first := &blockingOpenSession{started: make(chan struct{}, 2)}
	second := &blockingOpenSession{started: make(chan struct{}, 1)}
	client := &Client{
		streamLimit: defaultMinStreams,
		sessions:    []clientSession{first, second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 2)
	go func() {
		_, err := client.openStream(ctx)
		result <- err
	}()
	select {
	case <-first.started:
	case <-time.After(time.Second):
		t.Fatal("first session did not start opening")
	}
	go func() {
		_, err := client.openStream(ctx)
		result <- err
	}()
	select {
	case <-second.started:
	case <-first.started:
		cancel()
		<-result
		<-result
		t.Fatal("concurrent opens oversubscribed the first session")
	case <-time.After(time.Second):
		cancel()
		<-result
		<-result
		t.Fatal("second session did not start opening")
	}
	cancel()
	for range 2 {
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("openStream error = %v, want %v", err, context.Canceled)
		}
	}
}

func TestClientAliveFilterRetainsClosedSessionWithActiveStreams(t *testing.T) {
	replacementErr := errors.New("replacement dial failed")
	session := &failedOpenSession{active: 1, closed: true}
	client := &Client{
		dialer:         &errorDialer{err: replacementErr},
		protocol:       "smux",
		maxConnections: 1,
		streamLimit:    defaultMinStreams,
		sessions:       []clientSession{session},
	}
	if _, err := client.openStream(context.Background()); !errors.Is(err, replacementErr) {
		t.Fatalf("openStream error = %v, want %v", err, replacementErr)
	}
	if len(client.retired) != 1 || client.retired[0] != session {
		t.Fatalf("retired sessions = %#v, want closed active session", client.retired)
	}
	if got := session.closeCalls.Load(); got != 0 {
		t.Fatalf("closed active session was closed %d times during filtering", got)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if got := session.closeCalls.Load(); got != 1 {
		t.Fatalf("Client.Close closed retired session %d times, want 1", got)
	}
}

func TestClientPrunesDrainedRetiredSessions(t *testing.T) {
	dialErr := errors.New("dial failed")
	session := &failedOpenSession{}
	client := &Client{
		dialer:      &errorDialer{err: dialErr},
		protocol:    "smux",
		streamLimit: defaultMinStreams,
		retired:     []clientSession{session},
	}
	if _, err := client.openStream(context.Background()); !errors.Is(err, dialErr) {
		t.Fatalf("openStream error = %v, want %v", err, dialErr)
	}
	if len(client.retired) != 0 {
		t.Fatalf("retired sessions = %d, want 0", len(client.retired))
	}
	if got := session.closeCalls.Load(); got != 1 {
		t.Fatalf("drained retired session was closed %d times, want 1", got)
	}
}

func TestClientPendingPublicationAndAccountingAreAtomic(t *testing.T) {
	session := &accountingProbeSession{published: make(chan error, 1)}
	client := &Client{
		streamLimit: defaultMinStreams,
		sessions:    []clientSession{session},
	}
	session.client = client
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.openStream(ctx)
		result <- err
	}()
	select {
	case err := <-session.published:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream publication did not run")
	}

	client.mu.Lock()
	active, pending := session.NumStreams(), client.pending[session]
	client.mu.Unlock()
	if active != 1 || pending != 0 {
		t.Fatalf("accounting after publication = active %d + pending %d, want 1 + 0", active, pending)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("openStream error = %v, want %v", err, context.Canceled)
	}
}

func TestClientPendingLoadStopsDoubleCountingReflectedReservation(t *testing.T) {
	first := &blockingOpenSession{started: make(chan struct{}, 2), reflectOnOpen: true}
	second := &blockingOpenSession{started: make(chan struct{}, 1)}
	second.active.Store(1)
	client := &Client{
		streamLimit: defaultMinStreams,
		sessions:    []clientSession{first, second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 2)
	go func() {
		_, err := client.openStream(ctx)
		result <- err
	}()
	select {
	case <-first.started:
	case <-time.After(time.Second):
		t.Fatal("first session did not start opening")
	}
	go func() {
		_, err := client.openStream(ctx)
		result <- err
	}()
	select {
	case <-first.started:
	case <-second.started:
		cancel()
		<-result
		<-result
		t.Fatal("reflected reservation was counted twice")
	case <-time.After(time.Second):
		cancel()
		<-result
		<-result
		t.Fatal("second open did not start")
	}
	cancel()
	for range 2 {
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("openStream error = %v, want %v", err, context.Canceled)
		}
	}
}

type realSessionGateConn struct {
	net.Conn
	writes  atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (c *realSessionGateConn) Write(payload []byte) (int, error) {
	// The carrier request is the first write. Hold the first SMUX OPEN frame.
	if c.writes.Add(1) == 2 {
		close(c.started)
		<-c.release
	}
	return c.Conn.Write(payload)
}

type realSessionGateDialer struct {
	service     *Service
	dials       atomic.Int32
	started     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func (d *realSessionGateDialer) releaseOpen() {
	d.releaseOnce.Do(func() { close(d.release) })
}

func (d *realSessionGateDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	clientConnection, serverConnection := net.Pipe()
	go func() { _ = d.service.NewConnection(context.Background(), serverConnection) }()
	if d.dials.Add(1) == 1 {
		return &realSessionGateConn{
			Conn: clientConnection, started: d.started, release: d.release,
		}, nil
	}
	return clientConnection, nil
}

func TestClientRealSMUXPendingOpenCountedOnce(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 2)}
	dialer := &realSessionGateDialer{
		service: NewService(dispatcher),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	client, err := NewClient(Options{Dialer: dialer, Protocol: "smux", MaxStreams: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dialer.releaseOpen()
		_ = client.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	dispatchResults := make(chan error, 2)
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	dispatch := func() {
		clientLink, _ := linkPair()
		dispatchResults <- client.Dispatch(ctx, clientLink, destination)
	}
	go dispatch()
	select {
	case <-dialer.started:
	case <-ctx.Done():
		t.Fatal("first real SMUX OPEN did not reach the gated carrier write")
	}

	client.mu.Lock()
	if got := len(client.sessions); got != 1 {
		client.mu.Unlock()
		t.Fatalf("sessions before parallel open = %d, want 1", got)
	}
	first := client.sessions[0]
	active, pending := first.NumStreams(), client.pending[first]
	client.mu.Unlock()
	if active+pending != 1 {
		t.Fatalf("published first open accounting = active %d + pending %d, want one logical open", active, pending)
	}

	go dispatch()
	dialer.releaseOpen()
	for range 2 {
		select {
		case <-dispatcher.target:
		case <-ctx.Done():
			t.Fatal("parallel dispatch did not complete SMUX stream admission")
		}
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("parallel opens created %d real SMUX carriers, want one", got)
	}

	cancel()
	_ = client.Close()
	for range 2 {
		select {
		case <-dispatchResults:
		case <-time.After(time.Second):
			t.Fatal("Dispatch did not return after client shutdown")
		}
	}
}

func TestMagicDestination(t *testing.T) {
	if !IsDestination(X.TCPDestination(X.DomainAddress("sp.mux.sing-box.arpa"), 444)) {
		t.Fatal("magic SMUX destination was not recognized")
	}
	if !IsDestination(X.TCPDestination(&wrappedDomainAddress{domain: "sp.mux.sing-box.arpa"}, 444)) {
		t.Fatal("magic SMUX destination with wrapped domain was not recognized")
	}
	if IsDestination(X.TCPDestination(X.DomainAddress("example.com"), 444)) {
		t.Fatal("ordinary destination must not be recognized as SMUX")
	}
}
