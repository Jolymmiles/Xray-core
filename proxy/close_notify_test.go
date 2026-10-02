package proxy

import (
	gotls "crypto/tls"
	"errors"
	"io"
	stdnet "net"
	"testing"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// After Vision switches to direct copy the outer TLS state is stale, so closing
// it must not emit a close_notify record. The fork's hubs hand out the TLS
// connection behind physical-peer and statistics wrappers; suppression has to
// reach through both, leaving the peer with a bare EOF.
func TestSuppressOuterCloseNotifyThroughForkWrappers(t *testing.T) {
	generatedCertificate, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certificatePEM, privateKeyPEM := generatedCertificate.ToPEM()
	certificate, err := gotls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("parse generated TLS certificate: %v", err)
	}

	clientRaw, serverRaw := stdnet.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	deadline := time.Now().Add(3 * time.Second)
	if err := clientRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	clientTLS := gotls.Client(clientRaw, &gotls.Config{
		InsecureSkipVerify: true,
		MinVersion:         gotls.VersionTLS13,
		MaxVersion:         gotls.VersionTLS13,
	})
	serverTLS := gotls.Server(serverRaw, &gotls.Config{
		Certificates: []gotls.Certificate{certificate},
		MinVersion:   gotls.VersionTLS13,
		MaxVersion:   gotls.VersionTLS13,
	})
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS 1.3 handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server TLS 1.3 handshake: %v", err)
	}

	peer := &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.30"), Port: 443}
	accepted := &stat.CounterConnection{
		Connection: corenet.WithPhysicalPeer(peer, &xraytls.Conn{Conn: serverTLS}),
	}
	SuppressOuterCloseNotify(accepted)

	type readResult struct {
		n   int
		err error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, 64)
		n, err := clientRaw.Read(buffer)
		readDone <- readResult{n: n, err: err}
	}()
	if err := accepted.Close(); err != nil {
		t.Fatalf("close accepted connection: %v", err)
	}
	read := <-readDone
	if read.n != 0 || !errors.Is(read.err, io.EOF) {
		t.Fatalf("peer read after suppressed close = (%d bytes, %v), want a bare EOF without a TLS record", read.n, read.err)
	}
}
