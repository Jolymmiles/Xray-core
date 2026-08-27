package internet

import (
	"context"
	"io"
	stdnet "net"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/reality"
)

// TestAcceptedProxyProtocolConnKeepsTransportCapabilities pins the transport
// capabilities that downstream consumers require from every accepted RAW+
// REALITY connection. The accepted PROXY wrapper used to lose CloseWrite when
// any composition handed it forward without an outer provenance carrier,
// crashing the REALITY handshake with
//
//	panic: interface conversion: *internet.acceptedProxyProtocolConn is not
//	reality.CloseWriteConn: missing method CloseWrite
//
// The wrapper itself must stay transparent to transport capabilities so no
// future wiring can reintroduce the gap.
func TestAcceptedProxyProtocolConnKeepsTransportCapabilities(t *testing.T) {
	listener := new(DefaultListener)
	l, err := listener.Listen(context.Background(), &stdnet.TCPAddr{
		IP: stdnet.ParseIP("127.0.0.1"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	type dialResult struct {
		conn stdnet.Conn
		err  error
	}
	clientDone := make(chan dialResult, 1)
	go func() {
		c, err := stdnet.Dial("tcp", l.Addr().String())
		clientDone <- dialResult{c, err}
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverConn.Close() }()
	client := <-clientDone
	if client.err != nil {
		t.Fatal(client.err)
	}
	defer func() { _ = client.conn.Close() }()

	// The listener requires a valid PROXY header before any application byte.
	if _, err := io.WriteString(client.conn, "PROXY TCP4 198.51.100.7 203.0.113.1 12345 443\r\nx"); err != nil {
		t.Fatalf("failed to send PROXY header: %v", err)
	}
	bare := stdnet.Conn(newAcceptedProxyProtocolConn(serverConn))

	closeWriter, ok := bare.(reality.CloseWriteConn)
	if !ok {
		t.Fatalf("acceptedProxyProtocolConn lost reality.CloseWriteConn: %T", bare)
	}
	syscallConn, ok := bare.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		t.Fatalf("acceptedProxyProtocolConn lost syscall.Conn for tproxy/redirect consumers: %T", bare)
	}
	if _, err := syscallConn.SyscallConn(); err != nil {
		t.Fatalf("SyscallConn delegation failed: %v", err)
	}

	buffer := make([]byte, 1)
	if _, err := bare.Read(buffer); err != nil || buffer[0] != 'x' {
		t.Fatalf("payload read through PROXY wrapper failed: err=%v byte=%q", err, buffer[0])
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite delegation failed: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 8)
		_, err := client.conn.Read(buffer)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != io.EOF {
			t.Fatalf("expected EOF after server CloseWrite, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for EOF after CloseWrite delegation")
	}
}
