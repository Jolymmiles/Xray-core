//go:build !windows

package internet

import (
	"context"
	"io"
	stdnet "net"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/reality"

	corenet "github.com/xtls/xray-core/common/net"
)

// startUnixProxyClient dials the unix listener and writes a PROXY v1 header
// followed by one application byte, like a local reverse proxy would.
func startUnixProxyClient(t *testing.T, path string) stdnet.Conn {
	t.Helper()
	conn, err := stdnet.Dial("unix", path)
	if err != nil {
		t.Fatalf("failed to dial unix test listener: %v", err)
		return nil
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "PROXY TCP4 198.51.100.7 203.0.113.1 12345 443\r\nx"); err != nil {
		t.Fatalf("failed to send PROXY header: %v", err)
	}
	return conn
}

// TestUnixInboundProxyProtocolRealismCloseWriteContract pins the same
// xtls/reality tls.go Server() connection-type contract for inbounds listening
// on a unix domain socket with "acceptProxyProtocol": true and RAW+REALITY
// security.
//
// Regression context: accepted unix connections carry a RemoteAddr that cannot
// be canonicalized into an IP-based physical peer, so the listener lost the
// provenance carrier and handed the bare
// *internet.acceptedProxyProtocolConn to the REALITY handshake, which crashed:
//
//	panic: interface conversion: *internet.acceptedProxyProtocolConn is not
//	reality.CloseWriteConn: missing method CloseWrite
func TestUnixInboundProxyProtocolRealityCloseWriteContract(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "xray-reality.sock")
	listener := new(DefaultListener)
	l, err := listener.Listen(context.Background(), &stdnet.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	}, &SocketConfig{AcceptProxyProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	hubView := CapturePhysicalPeerListener(l) // mirrors tcp.ListenTCP wrap order
	defer func() { _ = hubView.Close() }()

	startUnixProxyClient(t, socketPath)

	conn := acceptWithDeadline(t, hubView)

	// Exact contract from xtls/reality tls.go Server():
	raw := conn
	if pc, ok := raw.(*proxyproto.Conn); ok {
		raw = pc.Raw()
	}
	closeWriter, ok := raw.(reality.CloseWriteConn)
	if !ok {
		t.Fatalf("REALITY handshake would panic: %T does not implement reality.CloseWriteConn", raw)
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed through the PROXY wrapper chain: %v", err)
	}

	buffer := make([]byte, 1)
	if _, err := raw.Read(buffer); err != nil {
		t.Fatalf("failed to read byte after PROXY header: %v", err)
	}
	accepted, ok := corenet.AcceptedProxyPeer(raw)
	if !ok || accepted != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("accepted PROXY peer = %s, ok=%v", accepted, ok)
	}
}
