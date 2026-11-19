package tls

import (
	"bytes"
	gotls "crypto/tls"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/transport/internet/tls/hellotest"
)

func ticketOf(t *testing.T, session *utls.ClientSessionState) []byte {
	t.Helper()
	ticket, _, err := session.ResumptionState()
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

// TestFailedDialKeepsANewerTicket pins that a connection which offered a
// ticket and then failed leaves the ticket another connection stored in the
// meantime. uTLS drops the ticket of a failed handshake from the cache; the
// cache behind the TLS settings gave that ticket up when it was offered, so
// what it holds by then came from a later handshake with the server.
func TestFailedDialKeepsANewerTicket(t *testing.T) {
	const name = "example.com"
	for fingerprintName, fingerprint := range map[string]utls.ClientHelloID{
		"firefox": utls.HelloFirefox_Auto,
		"chrome":  utls.HelloChrome_Auto,
	} {
		t.Run(fingerprintName, func(t *testing.T) {
			resumption := clientSessionResumption{configured: true, source: gotls.NewLRUClientSessionCache(1)}
			store := resumption.sessionCache(fingerprint)
			store.Put(name, sessionOf(t, gotls.VersionTLS13, 224))

			config := &utls.Config{ServerName: name, InsecureSkipVerify: true, OmitEmptyPsk: true}
			uConn, err := newUClient(&hellotest.Capture{}, config, fingerprint, resumption, nil)
			if err != nil {
				t.Fatal(err)
			}
			// A preset reads the cache when its hello is built.
			if hello := uConn.HandshakeState.Hello; hello == nil || len(hello.Raw) == 0 {
				if err := uConn.BuildHandshakeState(); err != nil {
					t.Fatal(err)
				}
			}
			if !offersPreSharedKey(uConn) {
				t.Fatal("the cached ticket was not offered")
			}

			newer := sessionOf(t, gotls.VersionTLS13, 225)
			store.Put(name, newer)
			// The peer never answers.
			if err := uConn.Handshake(); err == nil {
				t.Fatal("the handshake succeeded without a peer")
			}

			kept, ok := store.Get(name)
			if !ok {
				t.Fatal("the failed connection removed the ticket another connection had stored")
			}
			if !bytes.Equal(ticketOf(t, kept), ticketOf(t, newer)) {
				t.Fatal("the cache holds another ticket than the newer one")
			}
		})
	}
}
