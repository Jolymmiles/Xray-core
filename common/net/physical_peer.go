package net

import (
	"net/netip"
	"slices"
)

type physicalPeerConn struct {
	Conn
	peer Addr
}

func (c *physicalPeerConn) PhysicalPeer() Addr {
	return clonePhysicalPeer(c.peer)
}

// PhysicalPeer returns the immutable server-observed peer carried separately
// from a connection's effective RemoteAddr.
func PhysicalPeer(conn Conn) (Addr, bool) {
	carrier, ok := conn.(interface{ PhysicalPeer() Addr })
	if !ok {
		return nil, false
	}
	peer := clonePhysicalPeer(carrier.PhysicalPeer())
	return peer, peer != nil
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
	return &physicalPeerConn{Conn: conn, peer: peer}
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
	return &physicalPeerConn{Conn: wrapped, peer: peer}
}

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
