package net

import (
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

type physicalPeerTestConn struct {
	remote net.Addr
}

func (*physicalPeerTestConn) Read([]byte) (int, error)         { return 0, nil }
func (*physicalPeerTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*physicalPeerTestConn) Close() error                     { return nil }
func (*physicalPeerTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *physicalPeerTestConn) RemoteAddr() net.Addr           { return c.remote }
func (*physicalPeerTestConn) SetDeadline(time.Time) error      { return nil }
func (*physicalPeerTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*physicalPeerTestConn) SetWriteDeadline(time.Time) error { return nil }

type physicalPeerSyscallTestConn struct {
	*physicalPeerTestConn
}

type physicalPeerCloseWriteTestConn struct {
	*physicalPeerSyscallTestConn
	closed bool
}

func (c *physicalPeerCloseWriteTestConn) CloseWrite() error {
	c.closed = true
	return nil
}

type physicalPeerNetConnWrapper struct {
	Conn
}

type acceptedProxyPeerTestConn struct {
	*physicalPeerTestConn
	accepted netip.Addr
}

func (c *acceptedProxyPeerTestConn) AcceptedProxyPeer() netip.Addr { return c.accepted }

func (c *physicalPeerNetConnWrapper) NetConn() Conn { return c.Conn }

func (*physicalPeerSyscallTestConn) SyscallConn() (syscall.RawConn, error) { return nil, nil }

func TestPhysicalPeerWrapperPreservesOnlyExistingSyscallCapability(t *testing.T) {
	plain := &physicalPeerTestConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}}
	wrappedPlain := CapturePhysicalPeer(plain)
	if _, ok := wrappedPlain.(syscall.Conn); ok {
		t.Fatal("plain virtual connection gained syscall.Conn")
	}
	if got := UnwrapPhysicalPeer(wrappedPlain); got != plain {
		t.Fatalf("unwrapped plain connection = %T, want original", got)
	}

	raw := &physicalPeerSyscallTestConn{physicalPeerTestConn: plain}
	wrappedRaw := CapturePhysicalPeer(raw)
	if _, ok := wrappedRaw.(syscall.Conn); !ok {
		t.Fatal("raw connection lost syscall.Conn")
	}
	if got := UnwrapPhysicalPeer(wrappedRaw); got != raw {
		t.Fatalf("unwrapped raw connection = %T, want original", got)
	}
}

func TestPhysicalPeerWrapperPreservesCloseWriteCapability(t *testing.T) {
	raw := &physicalPeerCloseWriteTestConn{physicalPeerSyscallTestConn: &physicalPeerSyscallTestConn{
		physicalPeerTestConn: &physicalPeerTestConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}},
	}}
	wrapped := CapturePhysicalPeer(raw)
	closeWriter, ok := wrapped.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("captured connection lost CloseWrite: %T", wrapped)
	}
	if err := closeWriter.CloseWrite(); err != nil || !raw.closed {
		t.Fatalf("CloseWrite = %v, delegated = %v", err, raw.closed)
	}
	if _, ok := wrapped.(syscall.Conn); !ok {
		t.Fatalf("captured connection lost syscall.Conn: %T", wrapped)
	}
}

func TestPhysicalPeerSurvivesTLSAndRealityStyleNetConnWrappers(t *testing.T) {
	raw := CapturePhysicalPeer(&physicalPeerTestConn{
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 443},
	})
	wrapper := &physicalPeerNetConnWrapper{Conn: &physicalPeerNetConnWrapper{Conn: raw}}
	peer, ok := PhysicalPeer(wrapper)
	if !ok || peer.String() != "192.0.2.9:443" {
		t.Fatalf("physical peer through NetConn wrappers = %v, ok=%v", peer, ok)
	}
}

func TestAcceptedProxyPeerSurvivesConnectionWrappers(t *testing.T) {
	accepted := netip.MustParseAddr("198.51.100.7")
	source := CapturePhysicalPeer(&acceptedProxyPeerTestConn{
		physicalPeerTestConn: &physicalPeerTestConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 443}},
		accepted:             accepted,
	})
	wrapper := &physicalPeerTestConn{remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 0}}
	preserved := PreservePhysicalPeer(source, wrapper)

	got, ok := AcceptedProxyPeer(preserved)
	if !ok || got != accepted {
		t.Fatalf("accepted PROXY peer = %s, ok=%v, want %s", got, ok, accepted)
	}
	if got := preserved.RemoteAddr().String(); got != "203.0.113.99:0" {
		t.Fatalf("effective remote = %s, want rewritten address", got)
	}
}

func TestPeerProvenanceAddressSeparatesAcceptedProxyFromEffectiveRemote(t *testing.T) {
	effective := &net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 0}
	physical := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321}
	accepted := netip.MustParseAddr("198.51.100.7")
	address := WithPeerProvenanceAddress(effective, physical, accepted)

	if got := EffectiveAddress(address).String(); got != effective.String() {
		t.Fatalf("effective address = %s, want %s", got, effective)
	}
	if got, ok := PhysicalPeerFromAddress(address); !ok || got.String() != physical.String() {
		t.Fatalf("physical peer = %v, ok=%v", got, ok)
	}
	if got, ok := AcceptedProxyPeerFromAddress(address); !ok || got != accepted {
		t.Fatalf("accepted PROXY peer = %s, ok=%v, want %s", got, ok, accepted)
	}
}
