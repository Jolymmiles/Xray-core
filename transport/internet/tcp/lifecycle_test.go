package tcp

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func reserveTCPPort(t *testing.T) xnet.Port {
	t.Helper()
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*stdnet.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return xnet.Port(port)
}

func TestListenTCPClosesListenerAfterConfigurationError(t *testing.T) {
	port := reserveTCPPort(t)
	settings := &internet.MemoryStreamConfig{
		ProtocolName: "tcp",
		ProtocolSettings: &Config{HeaderSettings: &serial.TypedMessage{
			Type: "xray.test.missing.HeaderConfig",
		}},
	}

	listener, err := ListenTCP(context.Background(), xnet.LocalHostIP, port, settings, func(stat.Connection) {})
	if err == nil {
		listener.Close()
		t.Fatal("expected invalid header configuration to fail")
	}

	rebound, err := stdnet.Listen("tcp4", stdnet.JoinHostPort("127.0.0.1", port.String()))
	if err != nil {
		t.Fatalf("listener remained open after configuration error: %v", err)
	}
	rebound.Close()
}

func TestDialClosesConnectionAfterTLSHandshakeError(t *testing.T) {
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverResult <- err
			return
		}
		if _, err := conn.Write([]byte("not a TLS record")); err != nil {
			serverResult <- err
			return
		}

		buffer := make([]byte, 4096)
		for {
			_, err = conn.Read(buffer)
			if err != nil {
				serverResult <- err
				return
			}
		}
	}()

	port := xnet.Port(listener.Addr().(*stdnet.TCPAddr).Port)
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     "tcp",
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{ServerName: "localhost"},
	}
	conn, err := Dial(context.Background(), xnet.TCPDestination(xnet.LocalHostIP, port), settings)
	if err == nil {
		conn.Close()
		t.Fatal("expected TLS handshake to fail")
	}

	select {
	case err := <-serverResult:
		if err == nil {
			t.Fatal("server read unexpectedly succeeded")
		}
		if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
			t.Fatalf("client connection remained open after handshake error: %v", err)
		}
		if err != io.EOF {
			t.Logf("connection closed with %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not observe client connection close")
	}
}

func TestDialClosesConnectionAfterHeaderConfigurationError(t *testing.T) {
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverResult <- err
			return
		}
		_, err = conn.Read(make([]byte, 1))
		serverResult <- err
	}()

	port := xnet.Port(listener.Addr().(*stdnet.TCPAddr).Port)
	settings := &internet.MemoryStreamConfig{
		ProtocolName: "tcp",
		ProtocolSettings: &Config{HeaderSettings: &serial.TypedMessage{
			Type: "xray.test.missing.HeaderConfig",
		}},
	}
	conn, err := Dial(context.Background(), xnet.TCPDestination(xnet.LocalHostIP, port), settings)
	if err == nil {
		conn.Close()
		t.Fatal("expected invalid header configuration to fail")
	}

	select {
	case err := <-serverResult:
		if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
			t.Fatalf("client connection remained open after header configuration error: %v", err)
		}
		if err != io.EOF {
			t.Logf("connection closed with %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not observe client connection close")
	}
}
