package http_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
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

// enteringConn reports when a Write starts.
type enteringConn struct {
	net.Conn
	writing chan struct{}
}

func (c *enteringConn) Write(b []byte) (int, error) {
	select {
	case c.writing <- struct{}{}:
	default:
	}
	return c.Conn.Write(b)
}

// TestCloseEndsAFirstWriteBlockedOnItsHeader closes a connection whose first
// Write is blocked sending the response header to a peer that does not read.
// Close must reach the underlying connection, which ends the Write, rather
// than wait for the Write.
func TestCloseEndsAFirstWriteBlockedOnItsHeader(t *testing.T) {
	auth, err := NewAuthenticator(context.Background(), &Config{
		Response: &ResponseConfig{
			Version: &Version{Value: "1.1"},
			Status:  &Status{Code: "200", Reason: "OK"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	local, peer := net.Pipe()
	defer peer.Close()
	inner := &enteringConn{Conn: local, writing: make(chan struct{}, 1)}
	server := NewConn(inner, NoOpReader{}, auth.GetServerWriter(), NoOpWriter{}, NoOpWriter{}, NoOpWriter{})

	wrote := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte("payload"))
		wrote <- err
	}()
	select {
	case <-inner.writing:
	case <-time.After(5 * time.Second):
		t.Fatal("the first Write did not start")
	}

	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for a Write blocked on its header and never closed the connection")
	}
	select {
	case err := <-wrote:
		if err == nil {
			t.Fatal("a Write to a closed connection succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the blocked Write")
	}
}

// gatedHeader holds its header until released.
type gatedHeader struct {
	Writer
	entered chan struct{}
	release chan struct{}
}

func (w *gatedHeader) Write(dst io.Writer) error {
	close(w.entered)
	<-w.release
	return w.Writer.Write(dst)
}

// TestWriteLosingToCloseSendsNothing lets Close claim the header and holds it
// while it writes the error header. A Write or CloseWrite that comes then must
// fail without touching the connection, so the peer gets the error header
// alone, not payload ahead of it or a half-close before it.
func TestWriteLosingToCloseSendsNothing(t *testing.T) {
	errorHeader := []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
	for name, lose := range map[string]func(*Conn) error{
		"Write": func(c *Conn) error {
			_, err := c.Write([]byte("payload"))
			return err
		},
		"CloseWrite": func(c *Conn) error { return c.CloseWrite() },
	} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			peer, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			raw, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			header := &gatedHeader{
				Writer:  NewHeaderWriter(buf.FromBytes(errorHeader)),
				entered: make(chan struct{}),
				release: make(chan struct{}),
			}
			server := NewConn(raw, NoOpReader{}, NoOpWriter{}, header, header, header)

			closed := make(chan error, 1)
			go func() { closed <- server.Close() }()
			select {
			case <-header.entered:
			case <-time.After(5 * time.Second):
				close(header.release)
				t.Fatal("Close did not start its error header")
			}
			lost := make(chan error, 1)
			go func() { lost <- lose(server) }()
			select {
			case err := <-lost:
				if err == nil {
					t.Errorf("%s succeeded on a connection Close had claimed", name)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("%s waited for Close", name)
			}
			close(header.release)
			select {
			case err := <-closed:
				if err != nil {
					t.Fatalf("Close: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not return")
			}

			if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(peer)
			if err != nil {
				t.Fatalf("the peer did not see the connection end: %v", err)
			}
			if !bytes.Equal(got, errorHeader) {
				t.Fatalf("the peer got %q, want the error header alone", got)
			}
		})
	}
}
