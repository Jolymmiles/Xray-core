package internet

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/reality"

	"github.com/xtls/xray-core/transport/internet/finalmask"
	custommask "github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
	"github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
)

// TestTcpmaskProxyRealityContractChain drives the exact production composition
// of transport/internet/tcp.ListenTCP: the system listener carries PROXY
// handling, the capture layer wraps it, and TcpmaskManager wraps both before
// any connection reaches reality.Server. Every built-in mask that can be
// constructed from public config must keep the accepted connection satisfying
// reality.CloseWriteConn, with half-close delivering FIN to the peer.
func TestTcpmaskProxyRealityContractChain(t *testing.T) {
	rows := []struct {
		name string
		mask finalmask.Tcpmask
	}{
		{name: "fragment", mask: &fragment.Config{}},
		{name: "sudoku", mask: &sudoku.Config{Password: "tcpmask-contract-secret", Ascii: "prefer_entropy"}},
		{name: "custom", mask: &custommask.TCPConfig{}},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			base, err := new(DefaultListener).Listen(context.Background(), &stdnet.TCPAddr{
				IP: stdnet.ParseIP("127.0.0.1"),
			}, &SocketConfig{AcceptProxyProtocol: true})
			if err != nil {
				t.Fatal(err)
			}
			hubView := CapturePhysicalPeerListener(base) // mirrors tcp.ListenTCP
			manager := finalmask.NewTcpmaskManager([]finalmask.Tcpmask{row.mask})
			listener, err := manager.WrapListener(hubView)
			if err != nil {
				t.Fatal(err)
			}
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
