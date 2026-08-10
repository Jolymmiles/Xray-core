package singmux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
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

type blockedHandshakeDialer struct{}

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

func TestNewClientSupportsOnlySMUX(t *testing.T) {
	for _, protocol := range []string{"yamux", "h2mux", "unknown"} {
		if _, err := NewClient(Options{Dialer: &serviceDialer{}, Protocol: protocol}); err == nil {
			t.Fatalf("protocol %q must be rejected in the SMUX-only stage", protocol)
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
