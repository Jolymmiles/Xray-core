package singmux

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
)

type serviceBrutalDialer struct {
	service       *Service
	serverOptions BrutalOptions
	clientApplied chan uint64
}

func (d *serviceBrutalDialer) DialContext(context.Context, X.Destination) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: serverConn})
	ctx = ContextWithServerBrutalOptions(ctx, d.serverOptions)
	go func() { _ = d.service.NewConnection(ctx, serverConn) }()
	return &brutalCarrierConn{Conn: clientConn, applied: d.clientApplied}, nil
}

func TestServiceBrutalNegotiatesWithoutRoutingControlStream(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 2)}
	service := NewService(dispatcher)
	serverApplied := make(chan uint64, 1)
	service.setBrutalOptions = func(_ net.Conn, rate uint64) error {
		serverApplied <- rate
		return nil
	}
	clientApplied := make(chan uint64, 1)
	client, err := NewClient(Options{
		Dialer:   &serviceBrutalDialer{service: service, serverOptions: BrutalOptions{Enabled: true, SendBPS: 70_000_000, ReceiveBPS: 60_000_000}, clientApplied: clientApplied},
		Protocol: "smux",
		Brutal:   BrutalOptions{Enabled: true, SendBPS: 90_000_000, ReceiveBPS: 80_000_000},
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
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(response)
	if got := response.String(); got != "hello" {
		t.Fatalf("ordinary stream response = %q, want hello", got)
	}
	if got := <-serverApplied; got != 70_000_000 {
		t.Fatalf("server applied rate = %d, want 70000000", got)
	}
	if got := <-clientApplied; got != 60_000_000 {
		t.Fatalf("client applied rate = %d, want 60000000", got)
	}
	select {
	case target := <-dispatcher.target:
		if target != destination {
			t.Fatalf("control stream reached router as %s", target)
		}
	case <-ctx.Done():
		t.Fatal("ordinary stream did not reach router")
	}
	select {
	case target := <-dispatcher.target:
		t.Fatalf("unexpected extra routed stream: %s", target)
	default:
	}
	cancel()
	<-errCh
}

func TestServiceBrutalRejectsMalformedReservedDestinationWithoutRouting(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	service := NewService(dispatcher)
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverCtx := session.ContextWithInbound(ctx, &session.Inbound{Conn: serverConn})
	serverCtx = ContextWithServerBrutalOptions(serverCtx, BrutalOptions{
		Enabled: true, SendBPS: 70_000_000, ReceiveBPS: 60_000_000,
	})
	go func() { _ = service.NewConnection(serverCtx, serverConn) }()
	if err := writeCarrierRequest(clientConn, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	carrier, err := localsmux.Client(clientConn, config)
	if err != nil {
		t.Fatal(err)
	}
	defer carrier.Close()
	stream, err := carrier.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := writeStreamRequest(stream, 0, X.TCPDestination(X.DomainAddress(brutalExchangeDomain), 1)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	if _, err := readBrutalResponse(stream); err == nil {
		t.Fatal("malformed reserved destination succeeded")
	}
	select {
	case target := <-dispatcher.target:
		t.Fatalf("malformed control stream reached router: %s", target)
	default:
	}
}

func TestServiceBrutalClosesCarrierAfterSocketControlFailure(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	service := NewService(dispatcher)
	service.setBrutalOptions = func(net.Conn, uint64) error {
		return errors.New("socket control failed")
	}
	clientConn, serverConn := net.Pipe()
	serverCtx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: serverConn})
	serverCtx = ContextWithServerBrutalOptions(serverCtx, BrutalOptions{
		Enabled: true, SendBPS: 70_000_000, ReceiveBPS: 60_000_000,
	})
	go func() { _ = service.NewConnection(serverCtx, serverConn) }()
	if err := writeCarrierRequest(clientConn, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	carrier, err := localsmux.Client(clientConn, config)
	if err != nil {
		t.Fatal(err)
	}
	defer carrier.Close()
	stream, err := carrier.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStreamRequest(stream, 0, X.TCPDestination(X.DomainAddress(brutalExchangeDomain), 0)); err != nil {
		t.Fatal(err)
	}
	if err := writeBrutalRequest(stream, 80_000_000); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	if _, err := readBrutalResponse(stream); err == nil {
		t.Fatal("socket control failure succeeded")
	}
	select {
	case <-carrier.CloseChan():
	case <-time.After(time.Second):
		t.Fatal("carrier remained open after socket control failure")
	}
}
