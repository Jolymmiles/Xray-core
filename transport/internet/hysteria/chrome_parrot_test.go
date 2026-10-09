package hysteria

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"golang.org/x/crypto/cryptobyte"
)

// chromeParrotHandshake completes a QUIC handshake whose client parrots Chrome,
// as the Hysteria dialer does unless disableChromeParrot is set. It returns
// the client's TLS state and the extensions of the ClientHello the server got.
func chromeParrotHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (tls.ConnectionState, []uint16) {
	t.Helper()
	generated, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	serverConfig.Certificates = []tls.Certificate{{
		Certificate: [][]byte{generated.Certificate},
		PrivateKey:  common.Must2(x509.ParsePKCS8PrivateKey(generated.PrivateKey)),
	}}
	serverConfig.NextProtos = []string{"h3"}
	var extensionsMu sync.Mutex
	var extensions []uint16
	serverConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		extensionsMu.Lock()
		defer extensionsMu.Unlock()
		if extensions == nil {
			extensions = slices.Clone(hello.Extensions)
		}
		return nil, nil
	}
	clientConfig.NextProtos = []string{"h3"}
	clientConfig.InsecureSkipVerify = true // #nosec G402 -- generated test certificate

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	listener, err := quic.Listen(serverConn, serverConfig, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := listener.Accept(ctx)
		accepted <- err
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		<-conn.HandshakeComplete()
		<-ctx.Done()
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	conn, err := quic.Dial(ctx, clientConn, listener.Addr(), clientConfig, &quic.Config{ChromeParrot: true})
	if err != nil {
		t.Fatal(err)
	}
	// The client completed its handshake, so Accept has returned or is about
	// to; read its result before cancel, which would make any error look like
	// the cancellation.
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState().TLS
	_ = conn.CloseWithError(0, "")
	cancel()
	<-served
	extensionsMu.Lock()
	defer extensionsMu.Unlock()
	return state, extensions
}

// The Chrome parrot of the apernet/quic-go version Hysteria 2.13.0 pins
// offers the trust_anchors extension (draft-ietf-tls-trust-anchor-ids), which
// the previous version did not. This pins that the extension is offered; it
// does not compare the whole ClientHello with a capture of Chrome.
func TestChromeParrotClientHelloOffersTrustAnchors(t *testing.T) {
	const extensionTrustAnchors = 0xca34
	_, extensions := chromeParrotHandshake(t, &tls.Config{}, &tls.Config{ServerName: "localhost"})
	if !slices.Contains(extensions, extensionTrustAnchors) {
		t.Fatalf("Chrome parrot ClientHello extensions %#04x lack trust_anchors (%#04x)", extensions, extensionTrustAnchors)
	}
}

// echConfig returns an ECHConfig for publicName (RFC 9849, Section 4) and its
// X25519 private key.
func echConfig(t *testing.T, publicName string) (config, privateKey []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddUint16(0xfe0d) // version
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1)     // config_id
		b.AddUint16(0x20) // DHKEM(X25519, HKDF-SHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(1) // HKDF-SHA256
			b.AddUint16(1) // AES-128-GCM
		})
		b.AddUint8(0) // maximum_name_length
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
		b.AddUint16(0) // extensions
	})
	return b.BytesOrPanic(), key.Bytes()
}

// The Hysteria dialer logs whether the server accepted ECH from the client's
// TLS state. Hysteria 2.13.0 fixed Chrome parroting reporting it as never
// accepted.
func TestChromeParrotReportsAcceptedECH(t *testing.T) {
	config, privateKey := echConfig(t, "public.example.com")
	var configList cryptobyte.Builder
	configList.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(config) })
	state, _ := chromeParrotHandshake(t,
		&tls.Config{EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: privateKey, SendAsRetry: true}}},
		&tls.Config{ServerName: "localhost", EncryptedClientHelloConfigList: configList.BytesOrPanic()},
	)
	if !state.ECHAccepted {
		t.Fatal("the Chrome parrot reports ECH as not accepted")
	}
}
