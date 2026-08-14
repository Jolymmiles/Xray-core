package splithttp

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	stdnet "net"
	"testing"

	quic "github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func h3TestSettings(t *testing.T) *internet.MemoryStreamConfig {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	return &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Path: "lifecycle"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:  []*tls.Certificate{tls.ParseCertificate(certificate)},
			NextProtocol: []string{"h3"},
		},
	}
}

func reserveUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*stdnet.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func assertUDPPortAvailable(t *testing.T, port int) {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp4", (&stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: port}).String())
	if err != nil {
		t.Fatalf("UDP port %d was not released: %v", port, err)
	}
	_ = conn.Close()
}

func TestHTTP3ListenerCloseReleasesUDPPort(t *testing.T) {
	port := reserveUDPPort(t)
	listener, err := ListenXH(context.Background(), xnet.LocalHostIP, xnet.Port(port), h3TestSettings(t), func(stat.Connection) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	assertUDPPortAvailable(t, port)
}

func TestHTTP3InitializationFailureReleasesUDPPort(t *testing.T) {
	port := reserveUDPPort(t)
	originalListen := listenQUICEarly
	listenQUICEarly = func(*quic.Transport, *stdtls.Config, *quic.Config) (http3.QUICListener, error) {
		return nil, errors.New("injected ListenEarly failure")
	}
	t.Cleanup(func() { listenQUICEarly = originalListen })

	if listener, err := ListenXH(context.Background(), xnet.LocalHostIP, xnet.Port(port), h3TestSettings(t), func(stat.Connection) {}); err == nil {
		_ = listener.Close()
		t.Fatal("ListenXH succeeded after ListenEarly failure")
	}
	assertUDPPortAvailable(t, port)
}
