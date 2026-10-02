package internet_test

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/reality"
	"google.golang.org/protobuf/proto"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
	custommask "github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
	"github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

// TestTcpmaskProxyRealityContractChain drives the production composition of
// transport/internet/tcp.ListenTCP: FinalMask listens through the system
// listener with PROXY handling, the TCP masks wrap every accepted connection,
// and the hub capture layer wraps the result before any connection reaches
// reality.Server. Every built-in mask that can be constructed from public
// config must keep the accepted connection satisfying reality.CloseWriteConn,
// with half-close delivering FIN to the peer, and must keep the server-observed
// peer separate from the PROXY-declared source.
func TestTcpmaskProxyRealityContractChain(t *testing.T) {
	rows := []struct {
		name string
		mask proto.Message
	}{
		{name: "fragment", mask: &fragment.Config{}},
		{name: "sudoku", mask: &sudoku.Config{Password: "tcpmask-contract-secret", Ascii: "prefer_entropy"}},
		{name: "custom", mask: &custommask.TCPConfig{}},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			streamSettings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{
				Tcpmasks:       []*serial.TypedMessage{serial.ToTypedMessage(row.mask)},
				SocketSettings: &internet.SocketConfig{AcceptProxyProtocol: true},
			})
			if err != nil {
				t.Fatal(err)
			}
			base, err := streamSettings.FinalMask.Listen(context.Background(), &stdnet.TCPAddr{
				IP: stdnet.ParseIP("127.0.0.1"),
			})
			if err != nil {
				t.Fatal(err)
			}
			listener := internet.CapturePhysicalPeerListener(base) // mirrors tcp.ListenTCP
			defer func() { _ = listener.Close() }()

			clientDone := make(chan stdnet.Conn, 1)
			go func() {
				conn, err := stdnet.Dial("tcp", listener.Addr().String())
				if err == nil {
					if _, werr := io.WriteString(conn, "PROXY TCP4 198.51.100.7 203.0.113.1 12345 443\r\nx"); werr != nil {
						_ = conn.Close()
						conn = nil
					}
				} else {
					conn = nil
				}
				clientDone <- conn
			}()

			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			client := <-clientDone
			if client == nil {
				t.Fatal("client failed to connect")
			}
			defer func() { _ = client.Close() }()

			if _, ok := row.mask.(*custommask.TCPConfig); ok {
				buffer := make([]byte, 1)
				if _, err := conn.Read(buffer); err != nil || buffer[0] != 'x' {
					t.Fatalf("failed to settle custom header auth: byte=%q err=%v", buffer[0], err)
				}
			}

			peer, ok := corenet.PhysicalPeer(conn)
			if !ok || peer.String() != client.LocalAddr().String() {
				t.Fatalf("%s physical peer = %v (ok=%v), want the TCP peer %v", row.name, peer, ok, client.LocalAddr())
			}
			if accepted, ok := corenet.AcceptedProxyPeer(conn); !ok || accepted.String() != "198.51.100.7" {
				t.Fatalf("%s accepted PROXY peer = %v (ok=%v), want 198.51.100.7", row.name, accepted, ok)
			}

			closeWriter, ok := conn.(reality.CloseWriteConn)
			if !ok {
				t.Fatalf("REALITY handshake would panic behind %s mask: %T lacks reality.CloseWriteConn", row.name, conn)
			}
			if err := closeWriter.CloseWrite(); err != nil {
				t.Fatalf("%s CloseWrite delegation failed: %v", row.name, err)
			}

			eofDone := make(chan error, 1)
			go func() {
				buffer := make([]byte, 8)
				_, err := client.Read(buffer)
				eofDone <- err
			}()
			select {
			case err := <-eofDone:
				if err != io.EOF {
					t.Fatalf("%s peer expected EOF after half-close, got %v", row.name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s timed out waiting for FIN after CloseWrite", row.name)
			}
		})
	}
}
