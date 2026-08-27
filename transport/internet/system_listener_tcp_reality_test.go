package internet

import (
	"context"
	"io"
	stdnet "net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/reality"

	corenet "github.com/xtls/xray-core/common/net"
)

// startRealityContractClient dials the listener like a proxied client would and
// writes a valid PROXY v1 header followed by one application byte.
func startRealityContractClient(t *testing.T, port int, header string) {
	t.Helper()
	conn, err := stdnet.Dial("tcp", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("failed to dial test listener: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, header+"x"); err != nil {
		t.Fatalf("failed to send PROXY header: %v", err)
	}
}

// acceptWithDeadline fails the test instead of hanging when the server side
// never accepts.
func acceptWithDeadline(t *testing.T, l stdnet.Listener) stdnet.Conn {
	t.Helper()
	type result struct {
		conn stdnet.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		t.Cleanup(func() { _ = r.conn.Close() })
		return r.conn
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for accepted connection")
		return nil
	}
}

// TestTCPListenerProxyProtocolRealismCloseWriteContract asserts the exact
// connection-type contract that github.com/xtls/reality tls.go Server() relies
// on when sockopt.acceptProxyProtocol is enabled. It uses the same listener
// composition as transport/internet/tcp ListenTCP: DefaultListener wraps the
// system listener with PROXY handling, and the TCP hub adds its own capture
// layer around it before connections reach the REALITY handshake.
//
// Regression context: *internet.acceptedProxyProtocolConn lost the ability to
// satisfy reality.CloseWriteConn on some wrapper compositions, crashing the
// accept goroutine with
//
//	panic: interface conversion: *internet.acceptedProxyProtocolConn is not
//	reality.CloseWriteConn: missing method CloseWrite
//
// whenever REALITY ran on top of a RAW transport inbound with
// "acceptProxyProtocol": true.
func TestTCPListenerProxyProtocolRealityCloseWriteContract(t *testing.T) {
	listener := new(DefaultListener)
	l, err := listener.Listen(context.Background(), &stdnet.TCPAddr{
		IP: stdnet.ParseIP("127.0.0.1"),
	}, &SocketConfig{AcceptProxyProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	hubView := CapturePhysicalPeerListener(l) // mirrors tcp.ListenTCP wrap order
	defer func() { _ = hubView.Close() }()

	startRealityContractClient(t, hubView.Addr().(*stdnet.TCPAddr).Port,
		"PROXY TCP4 198.51.100.7 203.0.113.1 12345 443\r\n")

	conn := acceptWithDeadline(t, hubView)

	// Exact contract from xtls/reality tls.go Server():
	//   raw := conn
	//   if pc, ok := conn.(*proxyproto.Conn); ok {
	//       raw = pc.Raw()
	//   }
	//   underlying := raw.(CloseWriteConn)
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

	// Fork behavior: provenance captured by the listener must survive the same
	// chain that feeds the REALITY handshake.
	if _, hasPeer := corenet.PhysicalPeer(raw); !hasPeer {
		t.Fatalf("%T lost PhysicalPeer provenance", raw)
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
