package wireguard

import (
	"context"
	"encoding/hex"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// stackConn is a TCP connection as the stack hands it over: it is its own buf.Writer.
type stackConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *stackConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *stackConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func (c *stackConn) Close() error {
	c.closed.Add(1)
	return nil
}

func (c *stackConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{10, 0, 0, 2}, Port: 1234}
}

// closingDispatcher does what an outbound does when the other side has no more to send.
type closingDispatcher struct {
	routing.Dispatcher
	conn       *stackConn
	dispatched bool
	closed     int32
}

func (d *closingDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	d.dispatched = true
	common.Close(link.Writer)
	d.closed = d.conn.closed.Load()
	return nil
}

func TestServerKeepsConnectionOpenWhenWriterCloses(t *testing.T) {
	conn := &stackConn{}
	dispatcher := &closingDispatcher{conn: conn}
	users := &sync.Map{}
	users.Store([32]byte{1}, &protocol.MemoryUser{
		Email:   "love@xray.com",
		Account: &MemoryAccount{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}},
	})
	s := &Server{
		ctx:        context.Background(),
		dispatcher: dispatcher,
		users:      users,
		dev:        authenticatedTestDevice(t, [32]byte{1}, "198.51.100.10:51820", "10.0.0.2/32"),
		presence:   newWireGuardPresence(),
	}
	s.presence.Observe([32]byte{1}, 1, netip.MustParseAddr("198.51.100.10"), session.PresenceScope{})
	s.HandleConnection(conn, net.TCPDestination(net.ParseAddress("192.0.2.1"), 443))

	if !dispatcher.dispatched {
		t.Fatal("the connection never reached the dispatcher")
	}
	if dispatcher.closed != 0 {
		t.Fatal("the connection was closed with its writer, while the peer may still be sending")
	}
	if got := conn.closed.Load(); got != 1 {
		t.Fatalf("connection closed %d times, want 1", got)
	}
}

// authenticatedTestDevice is a device whose only peer pub sits at endpoint and
// owns allowedIP, as after a handshake. It is never brought up.
func authenticatedTestDevice(t *testing.T, pub [32]byte, endpoint, allowedIP string) *device.Device {
	t.Helper()
	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet("public_key=" + hex.EncodeToString(pub[:]) + "\nendpoint=" + endpoint + "\nallowed_ip=" + allowedIP + "\n"); err != nil {
		t.Fatal(err)
	}
	return dev
}
