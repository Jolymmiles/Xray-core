package tls

import (
	gotls "crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

type helloExtension struct {
	id   uint16
	body []byte
}

// helloExtensions returns the extensions of a ClientHello, with or without
// its record header, in wire order.
func helloExtensions(t *testing.T, hello []byte) []helloExtension {
	t.Helper()
	fail := func() { t.Fatalf("malformed ClientHello of %d bytes", len(hello)) }
	rest := hello
	take := func(n int) []byte {
		if n > len(rest) {
			fail()
		}
		taken := rest[:n]
		rest = rest[n:]
		return taken
	}
	if len(rest) > 0 && rest[0] == 0x16 {
		take(5)
	}
	take(4 + 2 + 32)
	take(int(take(1)[0]))
	take(int(binary.BigEndian.Uint16(take(2))))
	take(int(take(1)[0]))
	if int(binary.BigEndian.Uint16(take(2))) != len(rest) {
		fail()
	}
	var extensions []helloExtension
	for len(rest) > 0 {
		id := binary.BigEndian.Uint16(take(2))
		extensions = append(extensions, helloExtension{id, take(int(binary.BigEndian.Uint16(take(2))))})
	}
	return extensions
}

func (e helloExtension) of(extensions []helloExtension) []byte {
	for _, extension := range extensions {
		if extension.id == e.id {
			return extension.body
		}
	}
	return nil
}

// sessionOf completes one handshake with a local server of the given TLS
// version and returns the session it leaves, with a ticket of ticketLen
// bytes: uTLS builds a ClientHello from a ticket without reading it.
func sessionOf(t *testing.T, version uint16, ticketLen int) *utls.ClientSessionState {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil, cert.DNSNames("session.test"))
	certPEM, keyPEM := certificate.ToPEM()
	pair, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{pair}, MinVersion: version, MaxVersion: version,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte{1}); err != nil {
			served <- err
			return
		}
		_, err = io.Copy(io.Discard, conn)
		served <- err
	}()

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Also on a failure below, so that the server's copy ends.
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cache := utls.NewLRUClientSessionCache(1)
	client := utls.UClient(raw, &utls.Config{
		ServerName: "session.test", InsecureSkipVerify: true, ClientSessionCache: cache,
	}, utls.HelloChrome_Auto)
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	// The ticket of a TLS 1.3 server follows its handshake.
	if _, err := io.ReadFull(client, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	session, ok := cache.Get("session.test")
	if !ok || session == nil {
		t.Fatalf("the local server left no session for TLS %#04x", version)
	}
	session.SetSessionTicket(make([]byte, ticketLen))
	return session
}
