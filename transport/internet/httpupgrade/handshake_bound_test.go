package httpupgrade_test

import (
	"context"
	"errors"
	"io"
	stdnet "net"
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

// With "unsafe" the dialer takes crypto/tls, whose handshake would wait for
// the first write and run outside the dial's context. A server that takes the
// ClientHello and answers nothing must still end the dial with its context,
// and the connection must be closed.
func TestDialUnsafeFingerprintEndsWithTheContext(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	hello := make(chan struct{}, 1)
	closed := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// take the ClientHello, answer nothing
		if n, _ := conn.Read(make([]byte, 4096)); n > 0 {
			hello <- struct{}{}
		}
		io.Copy(io.Discard, conn)
		closed <- struct{}{}
	}()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrades"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
			Fingerprint:          "unsafe",
		},
	}
	port := net.Port(listener.Addr().(*stdnet.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), port), streamSettings)
		if err == nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("dial through a silent TLS server succeeded")
		}
		select {
		case <-hello:
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
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the connection of the failed handshake is still open")
	}
}

// The handshake run in the dial still upgrades through a working server.
func TestDialUnsafeFingerprintUpgrades(t *testing.T) {
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrades"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
			Fingerprint:          "unsafe",
		},
	}
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
