package net

import (
	"net/netip"
	"slices"
	"syscall"
)

type physicalPeerConn struct {
	Conn
	peer                    Addr
	acceptedProxyPeer       netip.Addr
	acceptedProxyPeerSource acceptedProxyPeerSource
}

type physicalPeerAddress struct {
	effective               Addr
	peer                    Addr
	acceptedProxyPeer       netip.Addr
	acceptedProxyPeerSource acceptedProxyPeerSource
}

type acceptedProxyPeerSource interface {
	AcceptedProxyPeer() netip.Addr
}

func (a *physicalPeerAddress) Network() string { return a.effective.Network() }
func (a *physicalPeerAddress) String() string  { return a.effective.String() }

func (c *physicalPeerConn) PhysicalPeer() Addr {
	return clonePhysicalPeer(c.peer)
}

func (c *physicalPeerConn) AcceptedProxyPeer() netip.Addr {
	if peer := canonicalAcceptedProxyPeer(c.acceptedProxyPeer); peer.IsValid() {
		return peer
	}
	if c.acceptedProxyPeerSource == nil {
		return netip.Addr{}
	}
	return canonicalAcceptedProxyPeer(c.acceptedProxyPeerSource.AcceptedProxyPeer())
}

func (c *physicalPeerConn) acceptedProxyPeerProvider() acceptedProxyPeerSource {
	if c == nil {
		return nil
	}
	if c.acceptedProxyPeer.IsValid() || c.acceptedProxyPeerSource != nil {
		return c
	}
	return acceptedProxyPeerSourceFromConn(c.Conn)
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

// AcceptedProxyPeer returns the immutable source captured from a successfully
// parsed PROXY header. It is carried separately from both PhysicalPeer and the
// connection's routing-visible RemoteAddr.
func AcceptedProxyPeer(conn Conn) (netip.Addr, bool) {
	if conn == nil {
		return netip.Addr{}, false
	}
	if source, ok := conn.(acceptedProxyPeerSource); ok {
		peer := canonicalAcceptedProxyPeer(source.AcceptedProxyPeer())
		if peer.IsValid() {
			return peer, true
		}
	}
	if wrapper, ok := conn.(interface{ NetConn() Conn }); ok {
		nested := wrapper.NetConn()
		if nested != nil && nested != conn {
			return AcceptedProxyPeer(nested)
		}
	}
	return netip.Addr{}, false
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
	peer, hasPhysicalPeer := PhysicalPeer(source)
	acceptedProxyPeerSource := acceptedProxyPeerSourceFromConn(source)
	if !hasPhysicalPeer && acceptedProxyPeerSource == nil {
		return wrapped
	}
	return withPeerProvenance(peer, netip.Addr{}, acceptedProxyPeerSource, wrapped)
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
	return withPeerProvenance(peer, netip.Addr{}, acceptedProxyPeerSourceFromConn(wrapped), wrapped)
}

func withPhysicalPeer(peer Addr, conn Conn) Conn {
	return withPeerProvenance(peer, netip.Addr{}, acceptedProxyPeerSourceFromConn(conn), conn)
}

// WithPeerProvenance attaches both the raw server-observed peer and an already
// canonical accepted PROXY source to a virtual connection.
func WithPeerProvenance(peer Addr, acceptedProxyPeer netip.Addr, wrapped Conn) Conn {
	if wrapped == nil {
		return nil
	}
	return withPeerProvenance(peer, acceptedProxyPeer, nil, wrapped)
}

func withPeerProvenance(peer Addr, acceptedProxyPeer netip.Addr, acceptedProxyPeerSource acceptedProxyPeerSource, conn Conn) Conn {
	if acceptedProxyPeerSource == nil && !acceptedProxyPeer.IsValid() {
		acceptedProxyPeerSource = acceptedProxyPeerSourceFromConn(conn)
	}
	carrier := &physicalPeerConn{
		Conn:                    conn,
		peer:                    clonePhysicalPeer(peer),
		acceptedProxyPeer:       canonicalAcceptedProxyPeer(acceptedProxyPeer),
		acceptedProxyPeerSource: acceptedProxyPeerSource,
	}
	syscallConn, hasSyscall := conn.(syscall.Conn)
	closeWriter, hasCloseWrite := conn.(closeWriteConn)
	if !hasCloseWrite {
		if raw, ok := conn.(interface{ Raw() Conn }); ok {
			closeWriter, hasCloseWrite = raw.Raw().(closeWriteConn)
		}
	}
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

func acceptedProxyPeerSourceFromConn(conn Conn) acceptedProxyPeerSource {
	if conn == nil {
		return nil
	}
	if carrier, ok := conn.(interface {
		acceptedProxyPeerProvider() acceptedProxyPeerSource
	}); ok {
		return carrier.acceptedProxyPeerProvider()
	}
	if source, ok := conn.(acceptedProxyPeerSource); ok {
		return source
	}
	if wrapper, ok := conn.(interface{ NetConn() Conn }); ok {
		nested := wrapper.NetConn()
		if nested != nil && nested != conn {
			return acceptedProxyPeerSourceFromConn(nested)
		}
	}
	return nil
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
	return withPeerProvenanceAddress(effective, peer, netip.Addr{}, nil)
}

// WithPeerProvenanceAddress carries fixed peer provenance through APIs such as
// gRPC that retain only a connection's RemoteAddr.
func WithPeerProvenanceAddress(effective, peer Addr, acceptedProxyPeer netip.Addr) Addr {
	return withPeerProvenanceAddress(effective, peer, acceptedProxyPeer, nil)
}

func withPeerProvenanceAddress(effective, peer Addr, acceptedProxyPeer netip.Addr, acceptedProxyPeerSource acceptedProxyPeerSource) Addr {
	effective = clonePhysicalPeer(effective)
	peer = clonePhysicalPeer(peer)
	if effective == nil {
		return effective
	}
	acceptedProxyPeer = canonicalAcceptedProxyPeer(acceptedProxyPeer)
	if peer == nil && !acceptedProxyPeer.IsValid() && acceptedProxyPeerSource == nil {
		return effective
	}
	return &physicalPeerAddress{
		effective:               effective,
		peer:                    peer,
		acceptedProxyPeer:       acceptedProxyPeer,
		acceptedProxyPeerSource: acceptedProxyPeerSource,
	}
}

// PhysicalPeerFromAddress reads provenance from a carrier address.
func PhysicalPeerFromAddress(addr Addr) (Addr, bool) {
	carrier, ok := addr.(*physicalPeerAddress)
	if !ok {
		return nil, false
	}
	return CopyPhysicalPeer(carrier.peer)
}

// AcceptedProxyPeerFromAddress reads accepted PROXY provenance from an address
// carrier after the connection-context protocol has processed its header.
func AcceptedProxyPeerFromAddress(addr Addr) (netip.Addr, bool) {
	carrier, ok := addr.(*physicalPeerAddress)
	if !ok {
		return netip.Addr{}, false
	}
	if peer := canonicalAcceptedProxyPeer(carrier.acceptedProxyPeer); peer.IsValid() {
		return peer, true
	}
	if carrier.acceptedProxyPeerSource == nil {
		return netip.Addr{}, false
	}
	peer := canonicalAcceptedProxyPeer(carrier.acceptedProxyPeerSource.AcceptedProxyPeer())
	return peer, peer.IsValid()
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
	peer, hasPhysicalPeer := PhysicalPeer(conn)
	acceptedProxyPeerSource := acceptedProxyPeerSourceFromConn(conn)
	if !hasPhysicalPeer && acceptedProxyPeerSource == nil {
		return conn
	}
	return &physicalPeerRemoteAddrConn{
		Conn:   conn,
		remote: withPeerProvenanceAddress(conn.RemoteAddr(), peer, netip.Addr{}, acceptedProxyPeerSource),
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

func canonicalAcceptedProxyPeer(peer netip.Addr) netip.Addr {
	peer = peer.Unmap()
	if !peer.IsValid() || peer.IsUnspecified() || peer.IsLoopback() {
		return netip.Addr{}
	}
	return peer
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
