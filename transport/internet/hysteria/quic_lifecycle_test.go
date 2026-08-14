package hysteria

import (
	"context"
	"errors"
	stdnet "net"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func hysteriaTestSettings(t *testing.T) *internet.MemoryStreamConfig {
	t.Helper()
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	return &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Auth: "test", MasqType: "404"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(certificate)},
			PinnedPeerCertSha256: [][]byte{certificateHash[:]},
		},
		QuicParams: &internet.QuicParams{DisableChromeParrot: true, UdpHop: &internet.UdpHop{}},
	}
}

func reserveHysteriaUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*stdnet.UDPAddr).Port
	_ = conn.Close()
	return port
}

func assertHysteriaUDPPortAvailable(t *testing.T, port int) {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp4", (&stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: port}).String())
	if err != nil {
		t.Fatalf("UDP port %d was not released: %v", port, err)
	}
	_ = conn.Close()
}

func TestHysteriaListenerStatelessResetAndShutdown(t *testing.T) {
	port := reserveHysteriaUDPPort(t)
	originalRead := readStatelessResetKey
	readStatelessResetKey = func(key []byte) error {
		for i := range key {
			key[i] = byte(i + 1)
		}
		return nil
	}
	t.Cleanup(func() { readStatelessResetKey = originalRead })

	listener, err := Listen(context.Background(), xnet.LocalHostIP, xnet.Port(port), hysteriaTestSettings(t), func(stat.Connection) {})
	if err != nil {
		t.Fatal(err)
	}
	resetKey := listener.(*Listener).tr.StatelessResetKey
	if resetKey == nil || resetKey[0] != 1 || resetKey[len(resetKey)-1] != byte(len(resetKey)) {
		t.Fatalf("unexpected Hysteria stateless reset key: %v", resetKey)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	assertHysteriaUDPPortAvailable(t, port)
}

func TestHysteriaListenerCloseWaitsForAcceptedConnections(t *testing.T) {
	port := reserveHysteriaUDPPort(t)
	settings := hysteriaTestSettings(t)
	secondReadStarted := make(chan struct{})
	secondReadReturned := make(chan struct{})
	releaseHandler := make(chan struct{})
	handlerReturned := make(chan struct{})
	listener, err := Listen(context.Background(), xnet.LocalHostIP, xnet.Port(port), settings, func(conn stat.Connection) {
		defer close(handlerReturned)
		var payload [1]byte
		_, _ = conn.Read(payload[:])
		close(secondReadStarted)
		_, _ = conn.Read(payload[:])
		close(secondReadReturned)
		<-releaseHandler
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := Dial(context.Background(), xnet.TCPDestination(xnet.DomainAddress("localhost"), xnet.Port(port)), settings)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("x")); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	<-secondReadStarted
	closeReturned := make(chan error, 1)
	go func() { closeReturned <- listener.Close() }()
	<-secondReadReturned
	select {
	case err := <-closeReturned:
		close(releaseHandler)
		<-handlerReturned
		t.Fatalf("Close returned before accepted handler: %v", err)
	default:
	}
	close(releaseHandler)
	if err := <-closeReturned; err != nil {
		t.Fatal(err)
	}
}

func TestHysteriaResetKeyFailureReleasesUDPPort(t *testing.T) {
	port := reserveHysteriaUDPPort(t)
	originalRead := readStatelessResetKey
	readStatelessResetKey = func([]byte) error { return errors.New("injected random failure") }
	t.Cleanup(func() { readStatelessResetKey = originalRead })

	if listener, err := Listen(context.Background(), xnet.LocalHostIP, xnet.Port(port), hysteriaTestSettings(t), func(stat.Connection) {}); err == nil {
		_ = listener.Close()
		t.Fatal("Listen succeeded after reset-key generation failure")
	}
	assertHysteriaUDPPortAvailable(t, port)
}
