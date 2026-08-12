package net

import (
	"net/netip"
	"slices"
	"syscall"
)

type physicalPeerConn struct {
	Conn
	peer Addr
}

type physicalPeerAddress struct {
	effective Addr
	peer      Addr
}

func (a *physicalPeerAddress) Network() string { return a.effective.Network() }
func (a *physicalPeerAddress) String() string  { return a.effective.String() }

func (c *physicalPeerConn) PhysicalPeer() Addr {
	return clonePhysicalPeer(c.peer)
}

func (c *physicalPeerConn) NetConn() Conn { return c.Conn }

type physicalPeerSyscallConn struct {
	*physicalPeerConn
	syscall.Conn
}

type closeWriteConn interface {
	CloseWrite() error
}

type physicalPeerCloseWriteConn struct {
	*physicalPeerConn
	closeWriteConn
}

type physicalPeerSyscallCloseWriteConn struct {
	*physicalPeerConn
	syscall.Conn
	closeWriteConn
}

// PhysicalPeer returns the immutable server-observed peer carried separately
// from a connection's effective RemoteAddr.
func PhysicalPeer(conn Conn) (Addr, bool) {
	carrier, ok := conn.(interface{ PhysicalPeer() Addr })
	if ok {
		peer := clonePhysicalPeer(carrier.PhysicalPeer())
		return peer, peer != nil
	}
	if wrapper, ok := conn.(interface{ NetConn() Conn }); ok {
		return PhysicalPeer(wrapper.NetConn())
	}
	return nil, false
}

// CapturePhysicalPeer freezes the current RemoteAddr on a connection.
func CapturePhysicalPeer(conn Conn) Conn {
	if conn == nil {
		return nil
	}
	if _, ok := PhysicalPeer(conn); ok {
		return conn
	}
	peer := clonePhysicalPeer(conn.RemoteAddr())
	if peer == nil {
		return conn
	}
	return withPhysicalPeer(peer, conn)
}

// PreservePhysicalPeer copies captured provenance across a connection wrapper.
func PreservePhysicalPeer(source, wrapped Conn) Conn {
	if wrapped == nil {
		return nil
	}
	peer, ok := PhysicalPeer(source)
	if !ok {
		return wrapped
	}
	return withPhysicalPeer(peer, wrapped)
}

// WithPhysicalPeer attaches already captured provenance to a virtual connection.
func WithPhysicalPeer(peer Addr, wrapped Conn) Conn {
	if wrapped == nil {
		return nil
	}
	peer = clonePhysicalPeer(peer)
	if peer == nil {
		return wrapped
	}
	return withPhysicalPeer(peer, wrapped)
}

func withPhysicalPeer(peer Addr, conn Conn) Conn {
	carrier := &physicalPeerConn{Conn: conn, peer: peer}
	syscallConn, hasSyscall := conn.(syscall.Conn)
	closeWriter, hasCloseWrite := conn.(closeWriteConn)
	switch {
	case hasSyscall && hasCloseWrite:
		return &physicalPeerSyscallCloseWriteConn{physicalPeerConn: carrier, Conn: syscallConn, closeWriteConn: closeWriter}
	case hasSyscall:
		return &physicalPeerSyscallConn{physicalPeerConn: carrier, Conn: syscallConn}
	case hasCloseWrite:
		return &physicalPeerCloseWriteConn{physicalPeerConn: carrier, closeWriteConn: closeWriter}
	}
	return carrier
}

// UnwrapPhysicalPeer removes only the provenance wrapper.
func UnwrapPhysicalPeer(conn Conn) Conn {
	switch conn := conn.(type) {
	case *physicalPeerSyscallCloseWriteConn:
		return conn.physicalPeerConn.Conn
	case *physicalPeerCloseWriteConn:
		return conn.physicalPeerConn.Conn
	case *physicalPeerSyscallConn:
		return conn.physicalPeerConn.Conn
	case *physicalPeerConn:
		return conn.Conn
	default:
		return conn
	}
}

// CopyPhysicalPeer returns a value-owned supported network address.
func CopyPhysicalPeer(peer Addr) (Addr, bool) {
	peer = clonePhysicalPeer(peer)
	return peer, peer != nil
}

// WithPhysicalPeerAddress carries provenance through APIs that retain only a
// connection's RemoteAddr, such as gRPC peer contexts.
func WithPhysicalPeerAddress(effective, peer Addr) Addr {
	effective = clonePhysicalPeer(effective)
	peer = clonePhysicalPeer(peer)
	if effective == nil || peer == nil {
		return effective
	}
	return &physicalPeerAddress{effective: effective, peer: peer}
}

// PhysicalPeerFromAddress reads provenance from a carrier address.
func PhysicalPeerFromAddress(addr Addr) (Addr, bool) {
	carrier, ok := addr.(*physicalPeerAddress)
	if !ok {
		return nil, false
	}
	return CopyPhysicalPeer(carrier.peer)
}

// EffectiveAddress removes the provenance carrier without changing the
// routing-visible remote address.
func EffectiveAddress(addr Addr) Addr {
	carrier, ok := addr.(*physicalPeerAddress)
	if !ok {
		return addr
	}
	effective, _ := CopyPhysicalPeer(carrier.effective)
	return effective
}

// CarryPhysicalPeerInRemoteAddr preserves a captured peer in RemoteAddr for
// connection-context APIs.
func CarryPhysicalPeerInRemoteAddr(conn Conn) Conn {
	conn = CapturePhysicalPeer(conn)
	peer, ok := PhysicalPeer(conn)
	if !ok {
		return conn
	}
	return &physicalPeerRemoteAddrConn{
		Conn:   conn,
		remote: WithPhysicalPeerAddress(conn.RemoteAddr(), peer),
	}
}

type physicalPeerRemoteAddrConn struct {
	Conn
	remote Addr
}

func (c *physicalPeerRemoteAddrConn) RemoteAddr() Addr { return c.remote }

// CanonicalPhysicalPeer removes transport details and rejects peers that
// cannot identify a remote network host.
func CanonicalPhysicalPeer(peer Addr) (netip.Addr, bool) {
	var ip IP
	switch peer := peer.(type) {
	case *TCPAddr:
		ip = peer.IP
	case *UDPAddr:
		ip = peer.IP
	case *IPAddr:
		ip = peer.IP
	default:
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() {
		return netip.Addr{}, false
	}
	return addr, true
}

func clonePhysicalPeer(peer Addr) Addr {
	switch peer := peer.(type) {
	case *TCPAddr:
		if peer == nil {
			return nil
		}
		return &TCPAddr{IP: slices.Clone(peer.IP), Port: peer.Port, Zone: peer.Zone}
	case *UDPAddr:
		if peer == nil {
			return nil
		}
		return &UDPAddr{IP: slices.Clone(peer.IP), Port: peer.Port, Zone: peer.Zone}
	case *IPAddr:
		if peer == nil {
			return nil
		}
		return &IPAddr{IP: slices.Clone(peer.IP), Zone: peer.Zone}
	default:
		return nil
	}
}
