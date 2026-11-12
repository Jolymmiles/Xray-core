package reality

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/reality"
)

// fallbackServer runs Server on one accepted connection and returns the
// client side of it together with the channel Server's error arrives on.
func fallbackTestServer(t *testing.T, target net.Listener) (net.Conn, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	config := &reality.Config{
		DialContext: new(net.Dialer).DialContext,
		Type:        "tcp",
		Dest:        target.Addr().String(),
		ServerNames: map[string]bool{"example.com": true},
	}
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		_, err = reality.Server(context.Background(), conn, config)
		done <- err
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, done
}

// serveTarget accepts one connection, reads the request, answers with reply
// and then ends the connection with a reset or a FIN.
func serveFallbackTarget(t *testing.T, reply string, reset bool) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Write([]byte(reply))
		if reset {
			conn.(*net.TCPConn).SetLinger(0)
		}
		conn.Close()
	}()
	return ln
}

const fallbackReply = "HTTP/1.1 400 Bad Request\r\n\r\n"

// A client that stays silent after the target reset the fallback connection
// must not hold Server: the client side is closed instead of half-closed.
func TestFallbackTargetResetClosesClient(t *testing.T) {
	client, done := fallbackTestServer(t, serveFallbackTarget(t, fallbackReply, true))
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Server() = nil error for a fallback connection")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Server() still runs 3s after the target reset, held by a silent client")
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(client); err != nil && !isFallbackConnReset(err) {
		t.Fatalf("client read after the target reset: %v", err)
	}
}

// A target that ends with a FIN is still passed on as a half-close: the client
// reads the reply and EOF, and Server ends once the client closes too.
func TestFallbackTargetFINHalfClosesClient(t *testing.T) {
	client, done := fallbackTestServer(t, serveFallbackTarget(t, fallbackReply, false))
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != fallbackReply {
		t.Fatalf("client read %q, want %q", got, fallbackReply)
	}
	select {
	case err := <-done:
		t.Fatalf("Server() = %v before the client closed; the target's FIN must stay a half-close", err)
	case <-time.After(300 * time.Millisecond):
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Server() still runs 3s after the client closed")
	}
}

func isFallbackConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}
