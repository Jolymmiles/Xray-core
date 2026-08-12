package net

import (
	"net"
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

type physicalPeerNetConnWrapper struct {
	Conn
}

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
