package encoding

import (
	"context"
	"io"
	"net"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestRemoteAddrFromContext(t *testing.T) {
	tests := []struct {
		name                  string
		metadata              metadata.MD
		trustedXForwardedFor  []string
		expectedRemoteAddress string
	}{
		{
			name:                  "trust X-Forwarded-For when configured",
			metadata:              metadata.Pairs("X-Forwarded-For", "2.2.2.2, 3.3.3.3"),
			trustedXForwardedFor:  []string{"X-Forwarded-For"},
			expectedRemoteAddress: "2.2.2.2:0",
		},
		{
			name:                  "trust X-Forwarded-For with trusted marker",
			metadata:              metadata.Pairs("X-Forwarded-For", "4.4.4.4", "X-Trusted-CDN", "1"),
			trustedXForwardedFor:  []string{"X-Trusted-CDN"},
			expectedRemoteAddress: "4.4.4.4:0",
		},
		{
			name:                  "ignore X-Forwarded-For without trusted marker",
			metadata:              metadata.Pairs("X-Forwarded-For", "5.5.5.5"),
			trustedXForwardedFor:  []string{"X-Trusted-CDN"},
			expectedRemoteAddress: "127.0.0.1:12345",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := peer.NewContext(metadata.NewIncomingContext(context.Background(), test.metadata), &peer.Peer{
				Addr: &net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 12345,
				},
			})
			remoteAddr := remoteAddrFromContext(ctx, test.trustedXForwardedFor)
			if remoteAddr.String() != test.expectedRemoteAddress {
				t.Fatalf("unexpected remote address: %s", remoteAddr.String())
			}
		})
	}
}

type physicalPeerHunkConn struct {
	ctx context.Context
}

func (c physicalPeerHunkConn) Context() context.Context { return c.ctx }
func (physicalPeerHunkConn) Send(*Hunk) error           { return nil }
func (physicalPeerHunkConn) Recv() (*Hunk, error)       { return nil, io.EOF }
func (physicalPeerHunkConn) SendMsg(any) error          { return nil }
func (physicalPeerHunkConn) RecvMsg(any) error          { return io.EOF }

type physicalPeerMultiHunkConn struct {
	ctx context.Context
}

func (c physicalPeerMultiHunkConn) Context() context.Context { return c.ctx }
func (physicalPeerMultiHunkConn) Send(*MultiHunk) error      { return nil }
func (physicalPeerMultiHunkConn) Recv() (*MultiHunk, error)  { return nil, io.EOF }
func (physicalPeerMultiHunkConn) SendMsg(any) error          { return nil }
func (physicalPeerMultiHunkConn) RecvMsg(any) error          { return io.EOF }

func TestGRPCVirtualConnectionsCarryPhysicalPeer(t *testing.T) {
	effective := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345}
	physical := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: corenet.WithPhysicalPeerAddress(effective, physical),
	})
	connections := []net.Conn{
		NewHunkConn(physicalPeerHunkConn{ctx: ctx}, nil, nil),
		NewMultiHunkConn(physicalPeerMultiHunkConn{ctx: ctx}, nil, nil),
	}
	for _, conn := range connections {
		got, ok := corenet.PhysicalPeer(conn)
		if !ok || got.String() != physical.String() {
			t.Fatalf("%T physical peer = %v, ok=%v", conn, got, ok)
		}
		if got := conn.RemoteAddr().String(); got != effective.String() {
			t.Fatalf("%T effective remote = %s, want %s", conn, got, effective)
		}
	}
}

func TestGRPCContextSeparatesPhysicalPeerFromEffectiveRemote(t *testing.T) {
	effective := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345}
	physical := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: corenet.WithPhysicalPeerAddress(effective, physical),
	})

	if got := remoteAddrFromContext(ctx, nil).String(); got != effective.String() {
		t.Fatalf("effective remote = %s, want %s", got, effective)
	}
	got, ok := physicalPeerFromContext(ctx)
	if !ok || got.String() != physical.String() {
		t.Fatalf("physical peer = %v, ok=%v, want %s", got, ok, physical)
	}
}
