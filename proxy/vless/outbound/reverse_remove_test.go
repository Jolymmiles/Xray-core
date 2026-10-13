package outbound

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	proxymanConfig "github.com/xtls/xray-core/app/proxyman"
	proxyman "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

// carrierListener accepts the reverse's carrier connections, reads and
// discards what the client sends and never answers, so a handshake stalls.
type carrierListener struct {
	listener stdnet.Listener
	accepted chan *carrier
	conns    connOwner
}

// carrier is one accepted connection; ended is closed once the client closes
// or resets it.
type carrier struct {
	ended chan struct{}
}

func newCarrierListener(t *testing.T) *carrierListener {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &carrierListener{listener: listener, accepted: make(chan *carrier, 16)}
	t.Cleanup(func() {
		if !l.close() {
			t.Error("a carrier's reader did not end after its connection closed")
		}
	})
	go l.serve()
	return l
}

func (l *carrierListener) serve() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			return
		}
		if !l.conns.own(conn) {
			continue
		}
		c := &carrier{ended: make(chan struct{})}
		go func() {
			defer l.conns.done()
			// The read ends, with EOF or an error, when the carrier does.
			_, _ = io.Copy(io.Discard, conn)
			close(c.ended)
		}()
		select {
		case l.accepted <- c:
		default:
		}
	}
}

// close releases every connection, which also ends a stalled client dial
// when a failing test left one behind, and reports whether their readers
// ended.
func (l *carrierListener) close() bool {
	_ = l.listener.Close()
	return l.conns.close()
}

func (l *carrierListener) destination() net.Destination {
	return net.DestinationFromAddr(l.listener.Addr())
}

func (l *carrierListener) waitCarrier(t *testing.T) *carrier {
	t.Helper()
	// The reverse starts 2 s after the outbound is created.
	select {
	case c := <-l.accepted:
		return c
	case <-time.After(15 * time.Second):
		t.Fatal("the VLESS reverse did not connect to its server")
		return nil
	}
}

// newReverseClient starts an instance with a VLESS outbound with a reverse,
// tagged "bridge", connecting to server. The default outbound, which the
// bridged traffic takes, is freedom.
func newReverseClient(t *testing.T, server net.Destination, account *vless.Account, stream *internet.StreamConfig) (outbound.Manager, *Handler) {
	t.Helper()
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxymanConfig.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag:           "direct",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
			},
			{
				Tag:            "bridge",
				SenderSettings: serial.ToTypedMessage(&proxymanConfig.SenderConfig{StreamSettings: stream}),
				ProxySettings: serial.ToTypedMessage(&Config{Vnext: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(server.Address),
					Port:    uint32(server.Port),
					User:    &protocol.User{Account: serial.ToTypedMessage(account)},
				}}),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	ohm := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	return ohm, ohm.GetHandler("bridge").(*proxyman.Handler).GetOutbound().(*Handler)
}

func reverseAccount() *vless.Account {
	id := uuid.New()
	return &vless.Account{Id: id.String(), Reverse: &vless.Reverse{Tag: "bridged"}}
}

// closeWithin runs closeBridge, which removes or closes the "bridge" outbound,
// and fails the test if it takes longer than limit.
func closeWithin(t *testing.T, closeBridge func() error, limit time.Duration) {
	t.Helper()
	closed := make(chan error, 1)
	go func() { closed <- closeBridge() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(limit):
		t.Fatalf("closing the outbound did not return within %v", limit)
	}
}

func removeBridge(ohm outbound.Manager) func() error {
	return func() error { return ohm.RemoveHandler(context.Background(), "bridge") }
}

func waitCarrierEnded(t *testing.T, c *carrier) {
	t.Helper()
	select {
	case <-c.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the closed outbound left its reverse carrier open")
	}
}

// A removed VLESS outbound with a reverse must close its bridge and never
// start another: before removals closed handlers, it redialed its server
// every 2 s for the life of the process.
func TestRemovedReverseClosesItsBridge(t *testing.T) {
	server := newCarrierListener(t)
	ohm, h := newReverseClient(t, server.destination(), reverseAccount(), &internet.StreamConfig{})
	c := server.waitCarrier(t)

	closeWithin(t, removeBridge(ohm), 10*time.Second)
	waitCarrierEnded(t, c)

	if err := h.reverse.Start(); err == nil {
		t.Fatal("the removed outbound's reverse started again")
	}
	if err := h.reverse.monitor(); err != nil {
		t.Fatal(err)
	}
	h.reverse.mu.Lock()
	workers := len(h.reverse.workers)
	h.reverse.mu.Unlock()
	if workers != 0 {
		t.Fatalf("the removed outbound's reverse admitted %d bridge workers", workers)
	}
}
