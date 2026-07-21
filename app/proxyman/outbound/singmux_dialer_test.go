package outbound

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type returningOutbound struct {
	returned chan struct{}
}

type controlledOutbound struct {
	link chan *transport.Link
}

func (o *controlledOutbound) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	o.link <- link
	<-ctx.Done()
	return ctx.Err()
}

func (o *returningOutbound) Process(context.Context, *transport.Link, internet.Dialer) error {
	close(o.returned)
	return errors.New("carrier stopped")
}

func TestSingMuxDialerIsolatesCarrierPreface(t *testing.T) {
	outbound := &controlledOutbound{link: make(chan *transport.Link, 1)}
	dialer := newSMUXOutboundDialer(outbound, nil)
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
	dialer := newSMUXOutboundDialer(outbound, nil)
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
	dialer := newSMUXOutboundDialer(outbound, nil)
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
