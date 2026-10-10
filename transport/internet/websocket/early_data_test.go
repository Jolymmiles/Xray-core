package websocket_test

import (
	"context"
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
		port := tcp.PickPort()
		listener, err := ListenWS(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
			ProtocolName:     "websocket",
			ProtocolSettings: &Config{Path: "ws"},
		}, func(conn stat.Connection) {
			go func() {
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
		t.Cleanup(func() { _ = listener.Close() })

		conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, port), earlyDataSettings("ws"))
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
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.entered <- struct{}{}
		<-s.release
		upgrader := gorillaws.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
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
