package http_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	. "github.com/xtls/xray-core/transport/internet/headers/http"
)

// TestServerCloseRacingFirstWriteSendsOneResponse closes a server connection
// while its first Write runs, as removing the connection's user does. The
// peer must see one response header, either the configured one or the error
// one, never both.
func TestServerCloseRacingFirstWriteSendsOneResponse(t *testing.T) {
	auth, err := NewAuthenticator(context.Background(), &Config{
		Request: &RequestConfig{Uri: []string{"/"}},
		Response: &ResponseConfig{
			Version: &Version{Value: "1.1"},
			Status:  &Status{Code: "200", Reason: "OK"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	for i := range 50 {
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		server := auth.Server(raw)
		if _, err := auth.Client(client).Write([]byte("request")); err != nil {
			t.Fatal(err)
		}
		request := make([]byte, len("request"))
		if _, err := io.ReadFull(server, request); err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		wrote := make(chan struct{})
		go func() {
			<-start
			_, _ = server.Write([]byte("payload"))
			close(wrote)
		}()
		close(start)
		_ = server.Close()
		<-wrote

		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		response, _ := io.ReadAll(client)
		client.Close()
		if headers := bytes.Count(response, []byte("HTTP/1.1 ")); headers > 1 {
			t.Fatalf("iteration %d: the peer got %d response headers:\n%s", i, headers, response)
		}
	}
}
