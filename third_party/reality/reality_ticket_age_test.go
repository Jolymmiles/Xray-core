package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	utls "github.com/refraction-networking/utls"
)

type refusalAgePipe struct{ net.Conn }

func (p refusalAgePipe) CloseWrite() error { return p.Close() }

// No reply uses a refusal measured more than ticketShapeMaxAge ago: after an
// inconclusive refresh, a known ticket with a wrong binder gets the stored
// alert just before the limit and the target's own reply just after it.
// From the maintainer's round-5 review.
func TestRefusalAgeAtUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		keyMaterial, err := ecdh.X25519().NewPrivateKey(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		config := &Config{
			Type: "tcp", Dest: t.Name(), PrivateKey: keyMaterial,
			DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
		}
		label := []byte("refusal age local session")
		statefulTickets.put(config, label, &SessionState{
			version: VersionTLS13, cipherSuite: TLS_AES_128_GCM_SHA256,
			createdAt: uint64(time.Now().Unix()), secret: make([]byte, 32),
		}, time.Hour)
		t.Cleanup(func() { statefulTickets.get(config, label, true) })
		hs := &serverHandshakeStateTLS13{
			c: &Conn{config: config},
			clientHello: &clientHelloMsg{
				serverName: "example.com",
				pskModes:   []uint8{pskModeDHE}, pskIdentities: []pskIdentity{{label: label}},
				pskBinders: [][]byte{make([]byte, 32)},
			},
		}
		key, alpn := recordsKey(config, hs.clientHello)
		t.Cleanup(func() { GlobalTicketShapes.Delete(key) })
		previous := &TicketShape{
			RefusesBadBinder: true, BadBinder: decryptErrorAlert, badBinderClose: alertRefusal,
			refusalAt: time.Now().Add(-ticketShapeMaxAge + time.Second),
		}
		fresh := &TicketShape{
			Issues: true, Resumes: true, Lifetime: 3600, badBinderSession: &utls.ClientSessionState{},
		}
		storeTicketShape(config, key, hs.clientHello.serverName, alpn, fresh, previous)
		if refusal, valid, invalid := hs.inspectTicketHello(false); refusal == nil || valid || !invalid {
			t.Fatalf("expected a carried refusal before the limit, got %v, %v, %v", refusal, valid, invalid)
		}
		time.Sleep(2 * time.Second) // virtual clock
		refusal, valid, invalid := hs.inspectTicketHello(false)
		if valid || !invalid {
			t.Fatalf("expected a known ticket with an invalid binder, got %v, %v", valid, invalid)
		}
		if refusal != nil {
			local, peer := net.Pipe()
			defer peer.Close()
			defer local.Close()
			go closeAfterRefusal(local, refusalAgePipe{local}, refusal)
			wire, err := io.ReadAll(peer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, decryptErrorAlert) {
				t.Fatalf("unexpected refusal wire bytes % x", wire)
			}
			t.Fatalf("handshake wrote stale wire alert % x, age %v, fresh ticket profile age %v",
				wire, time.Since(refusal.refusalAt), time.Since(refusal.probed))
		}
	})
}
