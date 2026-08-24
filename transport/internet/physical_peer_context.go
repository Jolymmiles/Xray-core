package internet

import (
	"context"
	"net/netip"

	"github.com/xtls/xray-core/common/net"
)

type physicalPeerContextListener struct {
	net.Listener
}

func (l *physicalPeerContextListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return net.CarryPhysicalPeerInRemoteAddr(conn), nil
}

// PhysicalPeerContextListener carries provenance through connection-context
// APIs that retain only RemoteAddr.
func PhysicalPeerContextListener(listener net.Listener) net.Listener {
	return &physicalPeerContextListener{Listener: listener}
}

type physicalPeerContextKey struct{}

type physicalPeerContextValue struct {
	peer net.Addr
	conn net.Conn
}

// ContextWithPhysicalPeer freezes a connection peer before HTTP metadata can
// replace the virtual remote address.
func ContextWithPhysicalPeer(ctx context.Context, conn net.Conn) context.Context {
	conn = net.CapturePhysicalPeer(conn)
	peer, ok := net.PhysicalPeer(conn)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, physicalPeerContextKey{}, physicalPeerContextValue{peer: peer, conn: conn})
}

// PhysicalPeerFromContext returns a value copy of captured HTTP provenance.
func PhysicalPeerFromContext(ctx context.Context) (net.Addr, bool) {
	value, ok := ctx.Value(physicalPeerContextKey{}).(physicalPeerContextValue)
	if !ok {
		return nil, false
	}
	return net.CopyPhysicalPeer(value.peer)
}

// AcceptedProxyPeerFromContext returns parser-captured PROXY provenance after
// HTTP or another connection-context protocol has consumed the header.
func AcceptedProxyPeerFromContext(ctx context.Context) (netip.Addr, bool) {
	value, ok := ctx.Value(physicalPeerContextKey{}).(physicalPeerContextValue)
	if !ok {
		return netip.Addr{}, false
	}
	return net.AcceptedProxyPeer(value.conn)
}
