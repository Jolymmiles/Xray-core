package xmc

import (
	"io"
	net "net"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/reality"
)

// TestServerConnKeepsCloseWrite pins the transport capability that REALITY's
// server handshake requires behind this mask: the wrapped Minecraft-masked
// connection must implement reality.CloseWriteConn and forward half-close to
// the physical connection. Only the raw carrier field participates, so a
// minimal literal is sufficient and keeps crypto scaffolding out of the probe.
func TestServerConnKeepsCloseWrite(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	clientDone := make(chan stdnet.Conn, 1)
	go func() {
		conn, err := stdnet.Dial("tcp", listener.Addr().String())
		clientDone <- func() stdnet.Conn {
			if err != nil {
				return nil
			}
			if _, werr := io.WriteString(conn, "x"); werr != nil {
				_ = conn.Close()
				return nil
			}
			return conn
		}()
	}()

	srvRaw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvRaw.Close() }()
	client := <-clientDone
	if client == nil {
		t.Fatal("client failed to connect")
	}
	defer func() { _ = client.Close() }()

	var masked net.Conn = &serverConn{c: srvRaw}

	closeWriter, ok := masked.(reality.CloseWriteConn)
	if !ok {
		t.Fatalf("masked connection lost reality.CloseWriteConn: %T", masked)
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite delegation failed: %v", err)
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
			t.Fatalf("peer expected EOF after half-close, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for FIN after CloseWrite")
	}
	t.Log("CLOSEWRITE_XMC_OK")
}
