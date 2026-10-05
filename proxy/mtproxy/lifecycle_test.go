package mtproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type observedReadConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *observedReadConn) Read(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(b)
}

func TestMTProxyHandlerCloseInterruptsHandshake(t *testing.T) {
	handler, err := New(context.Background(), testHandlerConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	observed := &observedReadConn{Conn: server, started: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- handler.Process(context.Background(), corenet.Network_TCP, observed, nil) }()
	<-observed.started
	handler.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler shutdown left handshake blocked")
	}
}

type fallbackDispatcher struct {
	routing.Dispatcher
	link *transport.Link
}

func (d fallbackDispatcher) Dispatch(context.Context, corenet.Destination) (*transport.Link, error) {
	return d.link, nil
}

func TestFakeTLSFallbackStopsBothDirections(t *testing.T) {
	for _, direction := range []string{"client", "upstream", "context"} {
		t.Run(direction, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			requestReader, requestWriter := pipe.New(pipe.WithSizeLimit(4096))
			responseReader, responseWriter := pipe.New(pipe.WithSizeLimit(4096))
			defer requestReader.Interrupt()
			defer responseReader.Interrupt()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- relayFakeTLSFallback(ctx, server, fallbackDispatcher{link: &transport.Link{Reader: responseReader, Writer: requestWriter}}, &fakeTLSFallback{serverName: "cover.example", clientHello: []byte("hello")})
			}()
			initial, err := requestReader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			var captured [5]byte
			initial.Copy(captured[:])
			if !bytes.Equal(captured[:], []byte("hello")) {
				buf.ReleaseMulti(initial)
				t.Fatal("fallback changed initial bytes")
			}
			buf.ReleaseMulti(initial)
			switch direction {
			case "client":
				client.Close()
			case "upstream":
				responseWriter.Close()
			case "context":
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("fallback retained opposite relay after completion")
			}
			if err := responseWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("late"))}); err == nil {
				t.Fatal("fallback response link remains writable")
			}
		})
	}
}

func TestMalformedFakeTLSDoesNotSelectFallback(t *testing.T) {
	config := testHandlerConfig(t)
	config.FakeTls = &FakeTLSConfig{Enabled: true, Domains: []string{"cover.example"}}
	handler, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	client, server := net.Pipe()
	defer server.Close()
	go func() { defer client.Close(); _, _ = client.Write([]byte{0x16, 3, 1, 0, 3, 1, 0}) }()
	_, err = handler.acceptClient(server)
	var fallback *fakeTLSFallback
	if err == nil || errors.As(err, &fallback) {
		t.Fatalf("malformed ClientHello selected fallback: %v", err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("unexpected parse error: %v", err)
	}
}

type handshakeCompleteConn struct {
	net.Conn
	complete func()
	once     sync.Once
}

func (c *handshakeCompleteConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		c.once.Do(c.complete)
	}
	return c.Conn.SetDeadline(deadline)
}

func TestMTProxyRejectsReplacedSecretGeneration(t *testing.T) {
	handler, err := New(context.Background(), testHandlerConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	secret := testSecret(42)
	user := &protocol.MemoryUser{Email: "generation@example", Account: &MemoryAccount{Secret: secret}}
	if err := handler.AddUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	// No upstream connection should be attempted for a revoked handshake.
	handler.middle.Close()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	var replaceErr error
	conn := &handshakeCompleteConn{Conn: server, complete: func() {
		if replaceErr = handler.RemoveUser(context.Background(), user.Email); replaceErr == nil {
			replaceErr = handler.AddUser(context.Background(), user)
		}
	}}
	header, _, _ := buildClientHeader(t, secret, FrameModePaddedIntermediate, 1)
	go func() { _, _ = client.Write(header[:]) }()
	err = handler.Process(context.Background(), corenet.Network_TCP, conn, nil)
	if replaceErr != nil {
		t.Fatal(replaceErr)
	}
	if err == nil || !strings.Contains(err.Error(), "revoked during handshake") {
		t.Fatalf("old handshake joined replacement generation: %v", err)
	}
}

type preAuthWriteConn struct {
	net.Conn
	writeDeadline time.Time
}

func (c *preAuthWriteConn) SetDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	return c.Conn.SetDeadline(deadline)
}

func (c *preAuthWriteConn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	return c.Conn.SetWriteDeadline(deadline)
}
func (c *preAuthWriteConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestMTProxyFakeTLSServerHelloHasWriteDeadline(t *testing.T) {
	config := testHandlerConfig(t)
	config.FakeTls = &FakeTLSConfig{Enabled: true, Domains: []string{"cover.example"}}
	handler, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	secret := testSecret(44)
	if err := handler.AddUser(context.Background(), &protocol.MemoryUser{Email: "deadline@example", Account: &MemoryAccount{Secret: secret}}); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &preAuthWriteConn{Conn: server}
	hello := buildTestClientHello(t, secret, "cover.example", time.Now().Unix())
	go func() { _, _ = client.Write(hello) }()
	if err := handler.Process(context.Background(), corenet.Network_TCP, conn, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("did not reach ServerHello write: %v", err)
	}
	if conn.writeDeadline.IsZero() || time.Until(conn.writeDeadline) > 10*time.Second {
		t.Fatalf("ServerHello write lacks bounded pre-auth deadline: %s", conn.writeDeadline)
	}
}
