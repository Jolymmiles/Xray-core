package internet_test

import (
	"context"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func TestRegisterListenerController(t *testing.T) {
	var gotFd uintptr

	common.Must(internet.RegisterListenerController(func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			gotFd = fd
		})
	}))

	conn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
		IP: net.IPv4zero,
	}, nil)
	common.Must(err)
	common.Must(conn.Close())

	if gotFd == 0 {
		t.Error("expected none-zero fd, but actually 0")
	}
}

func TestProxyListenerPreservesRawRemoteAddr(t *testing.T) {
	listener, err := internet.ListenSystem(context.Background(), &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, &internet.SocketConfig{AcceptProxyProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	header := proxyproto.HeaderProxyFromAddrs(1,
		&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345},
		listener.Addr(),
	)
	if _, err := header.WriteTo(client); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "x"); err != nil {
		t.Fatal(err)
	}

	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	var payload [1]byte
	if _, err := io.ReadFull(server, payload[:]); err != nil {
		t.Fatal(err)
	}
	if got := server.RemoteAddr().(*net.TCPAddr).IP.String(); got != "198.51.100.7" {
		t.Fatalf("proxy RemoteAddr = %s; want 198.51.100.7", got)
	}
	raw, ok := internet.RawRemoteAddr(server)
	if !ok {
		t.Fatal("accepted PROXY connection did not expose raw remote address")
	}
	if got := raw.(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
		t.Fatalf("raw RemoteAddr = %s; want 127.0.0.1", got)
	}
}
