package splithttp_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// TestListenerCloseEndsServedConnections closes an HTTP/1.1 and HTTP/2
// listener while its server keeps a connection open for the next request,
// as it does for every XHTTP client between sessions. Removing an inbound
// closes its listener; the connection must end with it, or the client keeps
// sending to the removed inbound.
func TestListenerCloseEndsServedConnections(t *testing.T) {
	listenPort := tcp.PickPort()
	listener, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "/sh"},
	}, func(conn stat.Connection) { conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprint(conn, "GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.Close {
		t.Fatal("the server closed the connection after the response; the test needs it kept open")
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadByte()
	var netErr stdnet.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("the connection the server kept open still runs 5s after the listener closed")
	}
	if err == nil {
		t.Fatal("the server sent data after its listener closed")
	}
}
