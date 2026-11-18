package httpupgrade_test

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// failingServer listens for one connection, runs serve on it, and then
// reads it to the client's close. hello reports a ClientHello's first byte,
// closed a close by the client. Its cleanup closes the accepted connection
// and waits for the server goroutine, so a failing test leaves nothing
// behind.
type failingServer struct {
	port    net.Port
	hello   chan struct{}
	closed  chan struct{}
	release func()
}

func newFailingServer(t *testing.T, serve func(stdnet.Conn) bool) *failingServer {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &failingServer{
		port:   net.Port(listener.Addr().(*stdnet.TCPAddr).Port),
		hello:  make(chan struct{}),
		closed: make(chan struct{}),
	}
	accepted := make(chan stdnet.Conn, 1)
	served := make(chan struct{})
	var once sync.Once
	s.release = func() {
		once.Do(func() {
			listener.Close()
			select {
			case conn := <-accepted:
				conn.Close()
			default:
			}
		})
	}
	t.Cleanup(func() {
		s.release()
		<-served
	})
	go func() {
		defer close(served)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
		first := make([]byte, 1)
		if _, err := io.ReadFull(conn, first); err != nil || first[0] != 0x16 {
			return
		}
		close(s.hello)
		if !serve(conn) {
			return
		}
		if _, err := io.Copy(io.Discard, conn); err == nil {
			close(s.closed)
		}
	}()
	return s
}

func tlsSettings(fingerprint string) *internet.MemoryStreamConfig {
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	return &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrades"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
			Fingerprint:          fingerprint,
		},
	}
}

// dialAsync dials the server in a goroutine. Its cleanup releases the
// server's connection, which ends a dial that ignores its context, and waits
// for the goroutine.
func dialAsync(t *testing.T, ctx context.Context, server *failingServer, streamSettings *internet.MemoryStreamConfig) <-chan error {
	port := server.port
	done := make(chan error, 1)
	finished := make(chan struct{})
	t.Cleanup(func() {
		server.release()
		<-finished
	})
	go func() {
		defer close(finished)
		conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), port), streamSettings)
		if err == nil {
			conn.Close()
		}
		done <- err
	}()
	return done
}

// With "unsafe" the dialer takes crypto/tls, whose handshake would wait for
// the first write and run outside the dial's context. A server that takes the
// ClientHello and answers nothing must still end the dial with its context,
// and the connection must be closed.
func TestDialUnsafeFingerprintEndsWithTheContext(t *testing.T) {
	server := newFailingServer(t, func(stdnet.Conn) bool { return true })
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	select {
	case err := <-dialAsync(t, ctx, server, tlsSettings("unsafe")):
		if err == nil {
			t.Fatal("dial through a silent TLS server succeeded")
		}
		select {
		case <-server.hello:
		default:
			t.Fatalf("dial failed before its ClientHello reached the server: %v", err)
		}
		if elapsed := time.Since(start); elapsed < 450*time.Millisecond || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dial failed after %v with %v; want it ended by its 500ms context", elapsed.Round(time.Millisecond), err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial still runs 5s after its 500ms context ended")
	}
	select {
	case <-server.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the connection of the failed handshake is still open")
	}
}

// A server that answers the ClientHello with plaintext HTTP fails the
// handshake, not by the context: the client must close the connection at
// once rather than leave it to the garbage collector.
func TestDialClosesTheConnectionAfterAnHTTPAnswer(t *testing.T) {
	for _, fingerprint := range []string{"unsafe", "chrome"} {
		t.Run(fingerprint, func(t *testing.T) {
			server := newFailingServer(t, func(conn stdnet.Conn) bool {
				conn.Read(make([]byte, 4096))
				_, err := conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
				return err == nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			select {
			case err := <-dialAsync(t, ctx, server, tlsSettings(fingerprint)):
				if err == nil {
					t.Fatal("dial through an HTTP answer to the ClientHello succeeded")
				}
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("dial ended by its context: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("dial still runs 5s after the server answered HTTP")
			}
			select {
			case <-server.closed:
			case <-time.After(3 * time.Second):
				t.Fatal("the connection is still open 3s after the dial failed")
			}
		})
	}
}

// The handshake run in the dial still upgrades through a working server.
func TestDialUnsafeFingerprintUpgrades(t *testing.T) {
	streamSettings := tlsSettings("unsafe")
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			b := make([]byte, 4)
			if _, err := io.ReadFull(conn, b); err == nil {
				conn.Write(b)
			}
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "ping" {
		t.Fatalf("read %q, %v; want the echo", b, err)
	}
}
