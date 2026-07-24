package inbound

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
)

type retainingDispatcher struct {
	link chan *transport.Link
}

func (*retainingDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, fmt.Errorf("unexpected Dispatch call")
}

func (d *retainingDispatcher) DispatchLink(_ context.Context, _ X.Destination, link *transport.Link) error {
	d.link <- link
	return nil
}

func (*retainingDispatcher) Start() error      { return nil }
func (*retainingDispatcher) Close() error      { return nil }
func (*retainingDispatcher) Type() interface{} { return routing.DispatcherType() }

type noReadDeadlineConnection struct {
	stdnet.Conn
}

func (*noReadDeadlineConnection) SetReadDeadline(time.Time) error { return nil }

func TestVLESSMuxLinkRemainsUsableAfterProcessReturns(t *testing.T) {
	const userID = "00112233-4455-6677-8899-aabbccddeeff"
	account, err := (&vless.Account{Id: userID}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Level: 0, Email: "mux@example.com", Account: account}
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}

	policyManager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{policyManager: policyManager, validator: validator}
	dispatcher := &retainingDispatcher{link: make(chan *transport.Link, 1)}
	serverPipe, client := stdnet.Pipe()
	server := &noReadDeadlineConnection{Conn: serverPipe}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	ctx := c.ContextWithID(context.Background(), 1)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	ctx = session.ContextWithInbound(
		ctx,
		&session.Inbound{
			Source: X.TCPDestination(X.LocalHostIP, 12345),
			Local:  X.TCPDestination(X.LocalHostIP, 443),
		},
	)
	ctx = session.ContextWithContent(ctx, &session.Content{})
	processResult := make(chan error, 1)
	go func() {
		processResult <- handler.Process(ctx, X.Network_TCP, server, dispatcher)
	}()

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    user,
		Command: protocol.RequestCommandMux,
		Address: X.DomainAddress("v1.mux.cool"),
	}
	if err := encoding.EncodeRequestHeader(client, request, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}

	var retained *transport.Link
	select {
	case retained = <-dispatcher.link:
	case <-time.After(time.Second):
		t.Fatal("VLESS request was not dispatched")
	}
	select {
	case err := <-processResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("VLESS Process did not return after dispatcher accepted the link")
	}

	payload := []byte("response-after-dispatch")
	writeResult := make(chan error, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				writeResult <- fmt.Errorf("panic while writing retained VLESS link: %v", recovered)
			}
		}()
		writeResult <- retained.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)})
	}()

	want := append([]byte{encoding.Version, 0}, payload...)
	type readOutcome struct {
		payload []byte
		err     error
	}
	readResult := make(chan readOutcome, 1)
	go func() {
		got := make([]byte, len(want))
		_, err := io.ReadFull(client, got)
		readResult <- readOutcome{payload: got, err: err}
	}()

	var readDone, writeDone bool
	deadline := time.After(time.Second)
	for !readDone || !writeDone {
		select {
		case outcome := <-readResult:
			readDone = true
			if outcome.err != nil {
				t.Fatal(outcome.err)
			}
			if string(outcome.payload) != string(want) {
				t.Fatalf("response = %x, want %x", outcome.payload, want)
			}
		case err := <-writeResult:
			writeDone = true
			if err != nil {
				t.Fatal(err)
			}
		case <-deadline:
			t.Fatal("retained VLESS response writer did not complete")
		}
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("late VLESS request read panicked after Process returned: %v", recovered)
		}
	}()
	mb, err := retained.Reader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err == nil {
		t.Fatal("late VLESS request read unexpectedly succeeded after client close")
	}
}
