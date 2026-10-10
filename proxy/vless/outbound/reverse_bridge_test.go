package outbound

import (
	"bytes"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	proxymanConfig "github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
)

// bridgeRelay sits between the bridge and the portal and reports when the
// bridge's first bytes have reached the portal and when the bridge closes its
// side.
type bridgeRelay struct {
	listener  stdnet.Listener
	portal    string
	upstream  chan struct{}
	ended     chan struct{}
	firstOnce sync.Once

	mu    sync.Mutex
	conns []stdnet.Conn
}

func newBridgeRelay(t *testing.T, portal net.Destination) *bridgeRelay {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &bridgeRelay{
		listener: listener,
		portal:   portal.NetAddr(),
		upstream: make(chan struct{}),
		ended:    make(chan struct{}),
	}
	t.Cleanup(r.close)
	go r.serve()
	return r
}

// serve relays only the first connection: a second one would be a redial the
// test does not expect.
func (r *bridgeRelay) serve() {
	bridge, err := r.listener.Accept()
	if err != nil {
		return
	}
	portal, err := stdnet.Dial("tcp", r.portal)
	if err != nil {
		_ = bridge.Close()
		return
	}
	r.mu.Lock()
	r.conns = append(r.conns, bridge, portal)
	r.mu.Unlock()
	go func() {
		_, _ = io.Copy(bridge, portal)
		_ = bridge.Close()
	}()
	buffer := make([]byte, 32*1024)
	for {
		n, err := bridge.Read(buffer)
		if n > 0 {
			if _, werr := portal.Write(buffer[:n]); werr != nil {
				break
			}
			r.firstOnce.Do(func() { close(r.upstream) })
		}
		if err != nil {
			break
		}
	}
	close(r.ended)
	_ = portal.Close()
}

func (r *bridgeRelay) close() {
	_ = r.listener.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, conn := range r.conns {
		_ = conn.Close()
	}
}

func (r *bridgeRelay) destination() net.Destination {
	return net.DestinationFromAddr(r.listener.Addr())
}

func echoXOR(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ 'c'
	}
	return out
}

// newReversePortal starts a portal: a VLESS inbound whose user owns the
// reverse tagged "portal", and a dokodemo inbound "entry" routed to it that
// sends every connection to echo.
func newReversePortal(t *testing.T, id string, echo net.Destination) (vlessPort, entryPort net.Port) {
	t.Helper()
	vlessPort, entryPort = tcp.PickPort(), tcp.PickPort()
	receiver := func(port net.Port) *serial.TypedMessage {
		return serial.ToTypedMessage(&proxymanConfig.ReceiverConfig{
			PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
			Listen:   net.NewIPOrDomain(net.LocalHostIP),
		})
	}
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxymanConfig.InboundConfig{}),
			serial.ToTypedMessage(&proxymanConfig.OutboundConfig{}),
			serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
				InboundTag: []string{"entry"},
				TargetTag:  &router.RoutingRule_Tag{Tag: "portal"},
			}}}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag:              "vless-in",
				ReceiverSettings: receiver(vlessPort),
				ProxySettings: serial.ToTypedMessage(&vlessinbound.Config{
					Users: []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{
						Id:      id,
						Reverse: &vless.Reverse{Tag: "portal"},
					})}},
					Decryption: "none",
				}),
			},
			{
				Tag:              "entry",
				ReceiverSettings: receiver(entryPort),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(echo.Address),
					RewritePort:     uint32(echo.Port),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:           "direct",
			ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	return vlessPort, entryPort
}

// echoThroughPortal sends one payload into the portal's entry and reports
// whether the bridge's echo came back.
func echoThroughPortal(entry net.Port) bool {
	conn, err := stdnet.DialTimeout("tcp", net.TCPDestination(net.LocalHostIP, entry).NetAddr(), 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("through the reverse bridge")
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false
	}
	return bytes.Equal(reply, echoXOR(payload))
}

// Removing an outbound whose reverse bridge is connected and authenticated
// (the portal routes traffic through it) must close that bridge promptly.
func TestRemovedReverseClosesAuthenticatedBridge(t *testing.T) {
	echo := tcp.Server{MsgProcessor: echoXOR, Listen: net.LocalHostIP}
	echoDest, err := echo.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })

	id := uuid.New()
	vlessPort, entryPort := newReversePortal(t, id.String(), echoDest)
	relay := newBridgeRelay(t, net.TCPDestination(net.LocalHostIP, vlessPort))
	account := &vless.Account{Id: id.String(), Reverse: &vless.Reverse{Tag: "bridged"}}
	ohm, h := newReverseClient(t, relay.destination(), account, &internet.StreamConfig{})

	// Readiness through the real path: the bridge's request has reached the
	// portal, then the portal echoes through the bridge. The portal registers
	// the bridge right after reading that request, so a few attempts may
	// still find no reverse outbound.
	select {
	case <-relay.upstream:
	case <-time.After(15 * time.Second):
		t.Fatal("the bridge sent nothing to the portal")
	}
	deadline := time.Now().Add(10 * time.Second)
	for !echoThroughPortal(entryPort) {
		if time.Now().After(deadline) {
			t.Fatal("the portal did not reach the echo server through the bridge")
		}
	}

	closeWithin(t, removeBridge(ohm), 10*time.Second)
	select {
	case <-relay.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the removed outbound left its authenticated bridge open")
	}
	if err := h.reverse.Start(); err == nil {
		t.Fatal("the removed outbound's reverse started again")
	}
}
