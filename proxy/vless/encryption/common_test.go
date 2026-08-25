package encryption

import (
	"net"
	"testing"

	transportstat "github.com/xtls/xray-core/transport/internet/stat"
)

type closeWriteConn struct {
	net.Conn
	closedWrite bool
}

func (c *closeWriteConn) CloseWrite() error {
	c.closedWrite = true
	return nil
}

func TestCommonConnCloseWriteDelegates(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	tracked := &closeWriteConn{Conn: client}
	connection := NewCommonConn(tracked, false)
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !tracked.closedWrite {
		t.Fatal("CloseWrite was not delegated")
	}
}

func TestCommonConnCloseWriteUnwrapsStatisticsConnection(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	tracked := &closeWriteConn{Conn: client}
	connection := NewCommonConn(&transportstat.CounterConnection{Connection: tracked}, false)
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !tracked.closedWrite {
		t.Fatal("CloseWrite was not delegated through statistics wrapper")
	}
}

func TestCommonConnCloseWriteIgnoresUnsupportedConnection(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	connection := NewCommonConn(client, false)
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}
