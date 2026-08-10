package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type returningOutbound struct {
	returned chan struct{}
}

type controlledOutbound struct {
	link     chan *transport.Link
	contexts chan context.Context
}

func (o *controlledOutbound) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	o.link <- link
	if o.contexts != nil {
		o.contexts <- ctx
	}
	<-ctx.Done()
	return ctx.Err()
}

func (o *returningOutbound) Process(context.Context, *transport.Link, internet.Dialer) error {
	close(o.returned)
	return errors.New("carrier stopped")
}

func TestSingMuxDialerIsolatesCarrierPreface(t *testing.T) {
	outbound := &controlledOutbound{link: make(chan *transport.Link, 1)}
	dialer := newSMUXOutboundDialer(outbound, nil, false)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	connection, err := dialer.DialContext(ctx, X.TCPDestination(X.DomainAddress("sp.mux.sing-box.arpa"), 444))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	link := <-outbound.link

	if _, err := connection.Write([]byte("preface")); err != nil {
		t.Fatal(err)
	}
	secondWrite := make(chan error, 1)
	go func() {
		_, err := connection.Write([]byte(strings.Repeat("x", 8192)))
		secondWrite <- err
	}()
	select {
	case err := <-secondWrite:
		t.Fatalf("second carrier write was not backpressured before preface consumption: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	first, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(first)
	if got := first.String(); got != "preface" {
		t.Fatalf("first carrier payload = %q, want isolated preface", got)
	}
	select {
	case err := <-secondWrite:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second carrier write did not resume after preface consumption")
	}
}

func TestSingMuxDialerClosesConnectionWhenOutboundReturns(t *testing.T) {
	outbound := &returningOutbound{returned: make(chan struct{})}
	dialer := newSMUXOutboundDialer(outbound, nil, false)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	connection, err := dialer.DialContext(ctx, X.TCPDestination(X.DomainAddress("sp.mux.sing-box.arpa"), 444))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	<-outbound.returned

	result := make(chan error, 1)
	go func() {
		_, err := connection.Read(make([]byte, 1))
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("read error = %v, want closed connection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("connection remained open after outbound returned")
	}
}

func TestSingMuxDialerDoesNotMutateParentOutbound(t *testing.T) {
	outbound := &controlledOutbound{link: make(chan *transport.Link, 1)}
	dialer := newSMUXOutboundDialer(outbound, nil, false)
	original := X.TCPDestination(X.DomainAddress("example.com"), 443)
	metadata := &session.Outbound{Target: original}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{metadata})
	connection, err := dialer.DialContext(ctx, X.TCPDestination(X.DomainAddress("sp.mux.sing-box.arpa"), 444))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	<-outbound.link
	if metadata.Target != original {
		t.Fatalf("parent target was mutated to %v", metadata.Target)
	}
}

func TestSingMuxDialerPublishesPhysicalConnectionForBrutal(t *testing.T) {
	outbound := &controlledOutbound{
		link:     make(chan *transport.Link, 1),
		contexts: make(chan context.Context, 1),
	}
	dialer := newSMUXOutboundDialer(outbound, nil, true)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	connection, err := dialer.DialContext(ctx, X.TCPDestination(X.DomainAddress("sp.mux.sing-box.arpa"), 444))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	carrierCtx := <-outbound.contexts
	controller := smuxCarrierControllerFromContext(carrierCtx)
	if controller == nil {
		t.Fatal("SMUX carrier controller was not installed in the carrier context")
	}
	physical, peer := net.Pipe()
	defer peer.Close()
	setCalled := make(chan struct{})
	var gotConn net.Conn
	var gotRate uint64
	controller.setBrutal = func(conn net.Conn, rate uint64) error {
		gotConn, gotRate = conn, rate
		close(setCalled)
		return nil
	}

	result := make(chan error, 1)
	go func() {
		result <- connection.(interface{ SetBrutal(uint64) error }).SetBrutal(123456)
	}()
	select {
	case err := <-result:
		t.Fatalf("SetBrutal returned before physical publication: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	publishSMUXPhysicalConnection(carrierCtx, physical, nil)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetBrutal did not unblock after physical publication")
	}
	select {
	case <-setCalled:
	case <-time.After(time.Second):
		t.Fatal("physical setter was not called")
	}
	if gotConn != physical || gotRate != 123456 {
		t.Fatalf("setter received conn=%p rate=%d, want conn=%p rate=123456", gotConn, gotRate, physical)
	}
}

func TestSingMuxDialerSetBrutalUnblocksOnDialError(t *testing.T) {
	outbound := &returningOutbound{returned: make(chan struct{})}
	dialer := newSMUXOutboundDialer(outbound, nil, true)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	connection, err := dialer.DialContext(ctx, X.TCPDestination(X.DomainAddress("sp.mux.sing-box.arpa"), 444))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	<-outbound.returned
	result := make(chan error, 1)
	go func() {
		result <- connection.(interface{ SetBrutal(uint64) error }).SetBrutal(123456)
	}()
	select {
	case err := <-result:
		if err == nil || err.Error() != "carrier stopped" {
			t.Fatalf("SetBrutal error = %v, want carrier stopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetBrutal remained blocked after dial error")
	}
}

func TestSingMuxDialerSetBrutalUnblocksWhenCarrierCloses(t *testing.T) {
	outbound := &controlledOutbound{link: make(chan *transport.Link, 1)}
	dialer := newSMUXOutboundDialer(outbound, nil, true)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	connection, err := dialer.DialContext(ctx, X.TCPDestination(X.DomainAddress("sp.mux.sing-box.arpa"), 444))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- connection.(interface{ SetBrutal(uint64) error }).SetBrutal(123456)
	}()
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("SetBrutal succeeded without a physical connection")
		}
	case <-time.After(time.Second):
		t.Fatal("SetBrutal remained blocked after carrier close")
	}
}

func TestHandlerDialPublishesOnlyLatestSuccessfulPhysicalConnection(t *testing.T) {
	physicalOne, peerOne := net.Pipe()
	defer peerOne.Close()
	physicalTwo, peerTwo := net.Pipe()
	defer peerTwo.Close()
	transientErr := errors.New("transient dial failure")
	attempt := 0
	protocol := fmt.Sprintf("smux-hook-test-%d", time.Now().UnixNano())
	if err := internet.RegisterTransportDialer(protocol, func(context.Context, X.Destination, *internet.MemoryStreamConfig) (stat.Connection, error) {
		attempt++
		switch attempt {
		case 1:
			return nil, transientErr
		case 2:
			return physicalOne, nil
		default:
			return physicalTwo, nil
		}
	}); err != nil {
		t.Fatal(err)
	}

	h := &Handler{streamSettings: &internet.MemoryStreamConfig{ProtocolName: protocol}}
	waitCtx, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()
	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	defer cancelCarrier()
	controller := newSMUXCarrierController(waitCtx, carrierCtx)
	ctx := context.WithValue(waitCtx, smuxCarrierControllerContextKey{}, controller)
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)

	if _, err := h.Dial(ctx, destination); !errors.Is(err, transientErr) {
		t.Fatalf("first Handler.Dial error = %v, want %v", err, transientErr)
	}
	select {
	case <-controller.ready:
		t.Fatal("transient Handler.Dial error published a terminal result")
	default:
	}
	if conn, err := h.Dial(ctx, destination); err != nil || conn != physicalOne {
		t.Fatalf("second Handler.Dial = (%v, %v), want physicalOne", conn, err)
	}
	if conn, err := h.Dial(ctx, destination); err != nil || conn != physicalTwo {
		t.Fatalf("third Handler.Dial = (%v, %v), want physicalTwo", conn, err)
	}
	conn, err := controller.waitPhysicalConnection()
	if err != nil {
		t.Fatal(err)
	}
	if conn != physicalTwo {
		t.Fatalf("selected physical connection = %p, want latest %p", conn, physicalTwo)
	}
}

func TestSMUXBrutalCarrierMarkerIsOptIn(t *testing.T) {
	for _, brutal := range []bool{false, true} {
		t.Run(fmt.Sprintf("brutal=%t", brutal), func(t *testing.T) {
			outbound := &controlledOutbound{
				link:     make(chan *transport.Link, 1),
				contexts: make(chan context.Context, 1),
			}
			dialer := newSMUXOutboundDialer(outbound, nil, brutal)
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
			connection, err := dialer.DialContext(ctx, X.TCPDestination(X.DomainAddress("sp.mux.sing-box.arpa"), 444))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			carrierCtx := <-outbound.contexts
			if got := IsSMUXBrutalCarrier(carrierCtx); got != brutal {
				t.Fatalf("IsSMUXBrutalCarrier = %t, want %t", got, brutal)
			}
		})
	}
}

func TestShouldPublishSMUXPhysicalConnectionSkipsDialerProxy(t *testing.T) {
	physical, peer := net.Pipe()
	defer physical.Close()
	defer peer.Close()

	if !shouldPublishSMUXPhysicalConnection(nil, physical, nil) {
		t.Fatal("direct physical connection should be published")
	}
	settings := &internet.MemoryStreamConfig{
		SocketSettings: &internet.SocketConfig{DialerProxy: "nested"},
	}
	if shouldPublishSMUXPhysicalConnection(settings, physical, nil) {
		t.Fatal("DialerProxy redirect result must not overwrite physical publication")
	}
}
