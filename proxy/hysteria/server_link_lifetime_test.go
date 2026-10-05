package hysteria

import (
	"context"
	"errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	hysteriatransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// detachedDispatcher hands the link to consumers that outlive DispatchLink,
// like mux/XUDP workers or the goroutines task.Run leaves behind when an
// outbound returns early. The link must stay memory-safe for them.
type detachedDispatcher struct {
	links chan transport.Link
}

func (*detachedDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*detachedDispatcher) Start() error      { return nil }
func (*detachedDispatcher) Close() error      { return nil }

func (*detachedDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, errors.New("not used by the Hysteria inbound")
}

func (d *detachedDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	d.links <- transport.Link{Reader: link.Reader, Writer: link.Writer}
	return nil
}

type serverLinkHarness struct {
	settings   *internet.MemoryStreamConfig
	server     net.Destination
	dispatcher *detachedDispatcher
	processed  chan error
}

// startServerLinkHarness runs a real Hysteria listener whose connection
// handler mirrors the inbound worker: Process, then close the connection.
func startServerLinkHarness(t *testing.T) *serverLinkHarness {
	t.Helper()
	settings := newHysteriaTestSettings()
	harness := &serverLinkHarness{
		settings:   settings,
		dispatcher: &detachedDispatcher{links: make(chan transport.Link, 1)},
		processed:  make(chan error, 1),
	}
	server := &Server{validator: account.NewValidator(), sessionPolicy: policy.SessionDefault()}
	listenCtx := hysteriatransport.ContextWithValidator(context.Background(), account.NewValidator())
	port := reserveUDPPort(t)
	listener, err := hysteriatransport.Listen(listenCtx, net.LocalHostIP, port, settings, func(conn stat.Connection) {
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
		err := server.Process(ctx, net.Network_TCP, conn, harness.dispatcher)
		_ = conn.Close()
		harness.processed <- err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	harness.server = net.TCPDestination(net.DomainAddress("localhost"), port)
	return harness
}

func newHysteriaTestSettings() *internet.MemoryStreamConfig {
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	return &internet.MemoryStreamConfig{
		ProtocolName:     "hysteria",
		ProtocolSettings: &hysteriatransport.Config{Auth: "test", MasqType: "404", UdpIdleTimeout: 60},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(certificate)},
			PinnedPeerCertSha256: [][]byte{certificateHash[:]},
		},
		QuicParams: &internet.QuicParams{DisableChromeParrot: true},
	}
}

func reserveUDPPort(t testing.TB) net.Port {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return net.Port(conn.LocalAddr().(*stdnet.UDPAddr).Port)
}

func (h *serverLinkHarness) dial(t *testing.T, datagram bool) stat.Connection {
	t.Helper()
	ctx := hysteriatransport.ContextWithDatagram(context.Background(), datagram)
	conn, err := hysteriatransport.Dial(ctx, h.server, h.settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// detachedLink waits until Server.Process has returned and the handler has
// closed the connection, then returns the link it dispatched.
func (h *serverLinkHarness) detachedLink(t *testing.T) transport.Link {
	t.Helper()
	var link transport.Link
	select {
	case link = <-h.dispatcher.links:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the Hysteria inbound to dispatch")
	}
	select {
	case <-h.processed:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Server.Process to return")
	}
	return link
}

func callAfterProcess(t *testing.T, operation string, call func() error) error {
	t.Helper()
	var err error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("%s after Server.Process returned panicked: %v", operation, recovered)
			}
		}()
		err = call()
	}()
	return err
}

func assertDetachedLinkFailsClosed(t *testing.T, link transport.Link) {
	t.Helper()
	response := buf.New()
	response.WriteString("late response")
	err := callAfterProcess(t, "WriteMultiBuffer", func() error {
		return link.Writer.WriteMultiBuffer(buf.MultiBuffer{response})
	})
	if err == nil {
		t.Fatal("WriteMultiBuffer on a closed Hysteria connection succeeded")
	}

	for range 4 {
		var payload buf.MultiBuffer
		err = callAfterProcess(t, "ReadMultiBuffer", func() error {
			var readErr error
			payload, readErr = link.Reader.ReadMultiBuffer()
			return readErr
		})
		buf.ReleaseMulti(payload)
		if err != nil {
			return
		}
	}
	t.Fatal("ReadMultiBuffer on a closed Hysteria connection kept returning data")
}

func TestServerUDPLinkFailsClosedAfterProcessReturns(t *testing.T) {
	harness := startServerLinkHarness(t)
	client := harness.dial(t, true)
	probe := buf.New()
	probe.WriteString("probe")
	if err := (&UDPWriter{writer: client, addr: "127.0.0.1:9"}).WriteMultiBuffer(buf.MultiBuffer{probe}); err != nil {
		t.Fatal(err)
	}
	assertDetachedLinkFailsClosed(t, harness.detachedLink(t))
}

func TestServerTCPLinkFailsClosedAfterProcessReturns(t *testing.T) {
	harness := startServerLinkHarness(t)
	client := harness.dial(t, false)
	if err := WriteTCPRequest(client, "127.0.0.1:9"); err != nil {
		t.Fatal(err)
	}
	assertDetachedLinkFailsClosed(t, harness.detachedLink(t))
}
