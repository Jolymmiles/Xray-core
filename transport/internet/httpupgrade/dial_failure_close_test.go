package httpupgrade_test

import (
	"bufio"
	"context"
	gotls "crypto/tls"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// peerCloseWait bounds how long the peer waits for the client to close the
// connection of a failed dial. The client has nothing left to wait for once
// the dial returns, so it should close at once.
const peerCloseWait = 3 * time.Second

var errStillOpen = errors.New("the client kept the connection open")

// waitForEnd reads r until the client ends the connection and reports how it
// ended: "EOF" or "RST", or errStillOpen once the read deadline passes.
func waitForEnd(r io.Reader) (string, error) {
	_, err := io.Copy(io.Discard, r)
	var netErr stdnet.Error
	switch {
	case err == nil:
		return "EOF", nil
	case errors.Is(err, syscall.ECONNRESET):
		return "RST", nil
	case errors.As(err, &netErr) && netErr.Timeout():
		return "", errStillOpen
	}
	return "", err
}

type peerEnd struct {
	how string
	err error
}

// dialFailingPeer dials a peer that runs serve on its one connection and
// fails the test unless the dial fails and the client then closes that
// connection. serve returns the reader the peer watches for the end of the
// connection: the TLS connection, whose end needs close_notify or a TCP end,
// or the TCP connection itself.
func dialFailingPeer(t *testing.T, tlsSettings *tls.Config, serve func(stdnet.Conn) (io.Reader, error)) {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	ended := make(chan peerEnd, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			ended <- peerEnd{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * peerCloseWait)); err != nil {
			ended <- peerEnd{err: fmt.Errorf("set deadline: %w", err)}
			return
		}
		reader, err := serve(conn)
		if err != nil {
			ended <- peerEnd{err: fmt.Errorf("serve: %w", err)}
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(peerCloseWait)); err != nil {
			ended <- peerEnd{err: fmt.Errorf("set read deadline: %w", err)}
			return
		}
		how, err := waitForEnd(reader)
		if err == nil && reader != io.Reader(conn) {
			// close_notify alone leaves the TCP connection open.
			var tcpHow string
			tcpHow, err = waitForEnd(conn)
			how += ", then TCP " + tcpHow
		}
		ended <- peerEnd{how: how, err: err}
	}()

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}
	if tlsSettings != nil {
		streamSettings.SecurityType = "tls"
		streamSettings.SecuritySettings = tlsSettings
	}
	port := net.Port(listener.Addr().(*stdnet.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, net.TCPDestination(net.LocalHostIP, port), streamSettings)
	if err == nil {
		conn.Close()
		t.Fatal("the dial succeeded")
	}
	t.Logf("the dial failed: %v", err)

	select {
	case end := <-ended:
		if errors.Is(end.err, errStillOpen) {
			t.Fatalf("the connection of the failed dial is still open %v after the dial failed", peerCloseWait)
		}
		if end.err != nil {
			t.Fatalf("the peer failed: %v", end.err)
		}
		t.Logf("the peer saw the connection end with %s", end.how)
	case <-time.After(4 * peerCloseWait):
		t.Fatal("the peer did not finish")
	}
}

func generateServerCertificate(t *testing.T) (gotls.Certificate, []byte) {
	t.Helper()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	pair, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair, ctHash[:]
}

func clientTLSSettings(fingerprint string, ctHash []byte) *tls.Config {
	return &tls.Config{
		ServerName:           "localhost",
		PinnedPeerCertSha256: [][]byte{ctHash},
		Fingerprint:          fingerprint,
	}
}

// rejectUpgrade reads the upgrade request and answers it with 404.
func rejectUpgrade(conn stdnet.Conn) (io.Reader, error) {
	if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")); err != nil {
		return nil, err
	}
	return conn, nil
}

// The server rejects the upgrade request: the dial fails reading the reply.
func TestDialClosesTheConnectionOfARejectedUpgrade(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		dialFailingPeer(t, nil, rejectUpgrade)
	})
	pair, ctHash := generateServerCertificate(t)
	for _, fingerprint := range []string{"unsafe", "chrome"} {
		t.Run(fingerprint, func(t *testing.T) {
			dialFailingPeer(t, clientTLSSettings(fingerprint, ctHash), func(conn stdnet.Conn) (io.Reader, error) {
				return rejectUpgrade(gotls.Server(conn, &gotls.Config{Certificates: []gotls.Certificate{pair}}))
			})
		})
	}
}

var errInjected = errors.New("injected failure")

// countingConn fails its writes or its reads and counts its closes.
type countingConn struct {
	failWrite bool
	closes    atomic.Int32
}

func (c *countingConn) Write(b []byte) (int, error) {
	if c.failWrite {
		return 0, errInjected
	}
	return len(b), nil
}
func (c *countingConn) Read([]byte) (int, error)         { return 0, errInjected }
func (c *countingConn) Close() error                     { c.closes.Add(1); return nil }
func (c *countingConn) LocalAddr() stdnet.Addr           { return &stdnet.TCPAddr{} }
func (c *countingConn) RemoteAddr() stdnet.Addr          { return &stdnet.TCPAddr{} }
func (c *countingConn) SetDeadline(time.Time) error      { return nil }
func (c *countingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countingConn) SetWriteDeadline(time.Time) error { return nil }

type connDialer struct{ conn stdnet.Conn }

func (d connDialer) Dial(context.Context, net.Address, net.Destination, *internet.SocketConfig) (stdnet.Conn, error) {
	return d.conn, nil
}
func (connDialer) DestIpAddress() stdnet.IP { return nil }

// Each failure after the connection exists closes it exactly once, whatever
// the TLS layer does before the request is written.
func TestDialClosesTheConnectionOfAFailedDialOnce(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failWrite bool
	}{
		{name: "request write fails", failWrite: true},
		{name: "reply read fails"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &countingConn{failWrite: tc.failWrite}
			internet.UseAlternativeSystemDialer(connDialer{conn})
			t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })

			streamSettings := &internet.MemoryStreamConfig{
				ProtocolName:     "httpupgrade",
				ProtocolSettings: &Config{Path: "httpupgrade"},
			}
			dialed, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, 1), streamSettings)
			if err == nil {
				dialed.Close()
				t.Fatal("the dial succeeded")
			}
			if !errors.Is(err, errInjected) {
				t.Fatalf("the dial failed with %v, want the injected failure", err)
			}
			if closes := conn.closes.Load(); closes != 1 {
				t.Fatalf("the connection of the failed dial was closed %d times, want 1", closes)
			}
		})
	}
}
