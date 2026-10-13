package websocket_test

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"net/http"
	"sync"
	"testing"
	"time"

	gorillaws "github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	. "github.com/xtls/xray-core/transport/internet/websocket"
)

// earlyDataSettings dials with early data: the first write dials and rides in
// the handshake when it fits Ed.
func earlyDataSettings(path string) *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: path, Ed: 2048},
	}
}

// runConcurrently runs every function in its own goroutine and fails the test
// if they do not all return within 10 s.
func runConcurrently(t *testing.T, fns ...func()) {
	t.Helper()
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent calls on the early-data connection did not return")
	}
}

// A proxy writes and reads its carrier from two goroutines and closes it from
// whichever finishes first, or from a third when the outbound closes. With
// early data the first write dials, so the connection it dials must reach the
// reader and Close safely.
func TestEarlyDataConnConcurrentReadWriteClose(t *testing.T) {
	t.Run("dial refused", func(t *testing.T) {
		listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dest := net.DestinationFromAddr(listener.Addr())
		listener.Close()
		conn, err := Dial(context.Background(), dest, earlyDataSettings("ws"))
		if err != nil {
			t.Fatal(err)
		}
		var writeErr, readErr error
		runConcurrently(t,
			func() { _, writeErr = conn.Write([]byte("early data")) },
			func() { _, readErr = conn.Read(make([]byte, 64)) },
			func() { _ = conn.Close() },
		)
		if writeErr == nil || readErr == nil {
			t.Fatalf("a refused dial: Write = %v, Read = %v, want errors", writeErr, readErr)
		}
	})

	t.Run("dialed", func(t *testing.T) {
		conn, err := Dial(context.Background(), listenEcho(t), earlyDataSettings("ws"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		payload := []byte("early data")
		echo := make([]byte, len(payload))
		var writeErr, readErr error
		runConcurrently(t,
			func() { _, writeErr = conn.Write(payload) },
			func() { _, readErr = conn.Read(echo) },
		)
		if writeErr != nil || readErr != nil || string(echo) != string(payload) {
			t.Fatalf("early data round trip: Write = %v, Read = %v, echo %q", writeErr, readErr, echo)
		}

		// A blocked read, two closes and a write, all at once. The read may
		// still get the write's echo; what it must not do is outlive Close.
		runConcurrently(t,
			func() { _, _ = conn.Read(make([]byte, 64)) },
			func() { _ = conn.Close() },
			func() { _ = conn.Close() },
			func() { _, _ = conn.Write(payload) },
		)
		if _, err := conn.Read(make([]byte, 64)); err == nil {
			t.Fatal("a read after Close returned no error")
		}
	})
}

// listenEcho starts a WebSocket server on path "ws" that echoes what it
// reads; its connections end when the client closes them or the test ends.
func listenEcho(t *testing.T) net.Destination {
	t.Helper()
	port := tcp.PickPort()
	var conns connOwner
	listener, err := ListenWS(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws"},
	}, func(conn stat.Connection) {
		if !conns.own(conn) {
			return
		}
		go func() {
			defer conns.done()
			defer conn.Close()
			b := make([]byte, 1024)
			for {
				n, err := conn.Read(b)
				if err != nil {
					return
				}
				if _, err := conn.Write(b[:n]); err != nil {
					return
				}
			}
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		if !conns.close() {
			t.Error("an echo connection's reader did not end after it closed")
		}
	})
	return net.TCPDestination(net.LocalHostIP, port)
}

// Before the first write there is no connection to set a deadline on: the
// deadline methods promoted from it dereferenced nil. They now fail, and
// once the write has dialed they reach the connection.
func TestEarlyDataDeadlines(t *testing.T) {
	conn, err := Dial(context.Background(), listenEcho(t), earlyDataSettings("ws"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	setters := []struct {
		name string
		set  func(time.Time) error
	}{
		{"SetDeadline", conn.SetDeadline},
		{"SetReadDeadline", conn.SetReadDeadline},
		{"SetWriteDeadline", conn.SetWriteDeadline},
	}
	for _, setter := range setters {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("%s before the first write panicked: %v", setter.name, recovered)
				}
			}()
			if err := setter.set(time.Now().Add(time.Minute)); err == nil {
				t.Errorf("%s before the first write returned no error", setter.name)
			}
		}()
	}

	if _, err := conn.Write([]byte("early data")); err != nil {
		t.Fatal(err)
	}
	for _, setter := range setters {
		if err := setter.set(time.Now().Add(time.Minute)); err != nil {
			t.Errorf("%s after the first write: %v", setter.name, err)
		}
	}
	// A deadline already past ends the read waiting for the echo's successor.
	echo := make([]byte, len("early data"))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	var timeout stdnet.Error
	if _, err := conn.Read(make([]byte, 1)); !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("a read past its deadline returned %v, want a timeout", err)
	}
}

// gatedUpgradeServer holds every WebSocket upgrade until the test releases it
// and reports when the upgraded connection ends.
type gatedUpgradeServer struct {
	dest       net.Destination
	entered    chan struct{}
	release    chan struct{}
	releaseNow func()
	ended      chan struct{}
}

func newGatedUpgradeServer(t *testing.T) *gatedUpgradeServer {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &gatedUpgradeServer{
		dest:    net.DestinationFromAddr(listener.Addr()),
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
		ended:   make(chan struct{}),
	}
	var endOnce sync.Once
	var conns connOwner
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.entered <- struct{}{}:
		default:
		}
		<-s.release
		upgrader := gorillaws.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if !conns.own(conn) {
			return
		}
		defer conns.done()
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				endOnce.Do(func() { close(s.ended) })
				return
			}
		}
	})}
	go func() { _ = server.Serve(listener) }()
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(s.release) })
		_ = server.Close()
		if !conns.close() {
			t.Error("an upgraded connection's handler did not end after it closed")
		}
	})
	s.releaseNow = func() { releaseOnce.Do(func() { close(s.release) }) }
	return s
}

// A Close that comes while the first write is still dialing finds nothing to
// close. The connection that dial returns must not outlive it.
func TestEarlyDataCloseDuringDialClosesTheDialedConnection(t *testing.T) {
	server := newGatedUpgradeServer(t)
	conn, err := Dial(context.Background(), server.dest, earlyDataSettings("/"))
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("early data"))
		written <- err
	}()
	select {
	case <-server.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first write did not dial")
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	server.releaseNow()
	select {
	case err := <-written:
		if err == nil {
			t.Error("a write whose dial finished after Close reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the write dialing across Close did not return")
	}
	select {
	case <-server.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection dialed across Close was left open")
	}
}
