package reality

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/reality"
)

// waitFor waits for done in a cleanup, with a bound, so a failing test
// leaves no goroutine behind and no goroutine reports after it returned.
func waitFor(t *testing.T, what string, done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Errorf("%s still runs 5s after the test ended", what)
	}
}

// fallbackTestServer runs Server on one accepted connection and returns the
// client side of it together with the channel Server's error arrives on. Its
// cleanup releases the target, closes both ends of the client connection,
// and waits for Server to return.
func fallbackTestServer(t *testing.T, target *fallbackTarget) (net.Conn, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := &reality.Config{
		DialContext: new(net.Dialer).DialContext,
		Type:        "tcp",
		Dest:        target.ln.Addr().String(),
		ServerNames: map[string]bool{"example.com": true},
	}
	done := make(chan error, 1)
	accepted := make(chan net.Conn, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		accepted <- conn
		_, err = reality.Server(context.Background(), conn, config)
		done <- err
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	t.Cleanup(func() {
		target.release()
		if client != nil {
			client.Close()
		}
		ln.Close()
		select {
		case conn := <-accepted:
			conn.Close()
		case <-finished:
		case <-time.After(5 * time.Second):
		}
		waitFor(t, "Server", finished)
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, done
}

const (
	fallbackRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	fallbackReply   = "HTTP/1.1 400 Bad Request\r\n\r\n"
)

// fallbackTarget is the fallback's destination.
type fallbackTarget struct {
	ln net.Listener
	// tail is what a FIN target read after its FIN.
	tail chan string
	// release lets a reset target reset the connection; it may run twice.
	release func()
}

// serveFallbackTarget accepts one connection, reads the whole request and
// answers with the reply. With reset, it resets the connection once released.
// Without, it half-closes, reads what the client sends after its FIN to EOF,
// and hands that back on tail. Its cleanup releases it, closes the accepted
// connection so blocked I/O returns, and waits for its goroutine.
func serveFallbackTarget(t *testing.T, reset bool) *fallbackTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	var once sync.Once
	target := &fallbackTarget{
		ln:      ln,
		tail:    make(chan string, 1),
		release: func() { once.Do(func() { close(released) }) },
	}
	accepted := make(chan net.Conn, 1)
	finished := make(chan struct{})
	t.Cleanup(func() {
		target.release()
		ln.Close()
		select {
		case conn := <-accepted:
			conn.Close()
		case <-finished:
		}
		waitFor(t, "the target", finished)
	})
	go func() {
		defer close(finished)
		defer close(target.tail)
		c, err := ln.Accept()
		if err != nil {
			// Server never dialled: the test fails on what the client reads.
			return
		}
		accepted <- c
		conn := c.(*net.TCPConn)
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		request := make([]byte, len(fallbackRequest))
		if _, err := io.ReadFull(conn, request); err != nil || string(request) != fallbackRequest {
			t.Errorf("target read %q, %v; want the request", request, err)
			return
		}
		if _, err := conn.Write([]byte(fallbackReply)); err != nil {
			t.Errorf("target write: %v", err)
			return
		}
		if reset {
			<-released
			if err := conn.SetLinger(0); err != nil {
				t.Errorf("SetLinger: %v", err)
			}
			return
		}
		if err := conn.CloseWrite(); err != nil {
			t.Errorf("target CloseWrite: %v", err)
			return
		}
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Errorf("target read after its FIN: %v", err)
		}
		target.tail <- string(got)
	}()
	return target
}

// A client that stays silent after the target reset the fallback connection
// must not hold Server: the client side is closed instead of half-closed.
func TestFallbackTargetResetClosesClient(t *testing.T) {
	target := serveFallbackTarget(t, true)
	client, done := fallbackTestServer(t, target)
	if _, err := client.Write([]byte(fallbackRequest)); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, len(fallbackReply))
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != fallbackReply {
		t.Fatalf("client read %q, %v; want the reply before the reset", reply, err)
	}
	target.release()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Server() = nil error for a fallback connection")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Server() still runs 3s after the target reset, held by a silent client")
	}
	if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("client read after Server returned: %d, %v; want EOF", n, err)
	}
}

// A target that ends with a FIN is still passed on as a half-close: the client
// reads the reply and EOF, what it sends after that still reaches the target,
// and Server ends once the client closes too.
func TestFallbackTargetFINHalfClosesClient(t *testing.T) {
	target := serveFallbackTarget(t, false)
	client, done := fallbackTestServer(t, target)
	if _, err := client.Write([]byte(fallbackRequest)); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil || string(got) != fallbackReply {
		t.Fatalf("client read %q, %v; want %q and EOF", got, err, fallbackReply)
	}
	const more = "sent after the target's FIN"
	if _, err := client.Write([]byte(more)); err != nil {
		t.Fatalf("client write after the target's FIN: %v", err)
	}
	client.Close()
	select {
	case got := <-target.tail:
		if got != more {
			t.Fatalf("target read %q after its FIN, want %q", got, more)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the target did not see the client's close")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Server() still runs 3s after the client closed")
	}
}
