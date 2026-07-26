package tls_test

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

var sessionResumptionTestID atomic.Uint64

// TestUClientSessionResumptionEnabled covers fingerprints whose stock
// ClientHello already advertises session_ticket and psk_key_exchange_modes.
// Only those may offer a resumption PSK, because only for those does adding it
// leave the impersonated client's fingerprint intact.
func TestUClientSessionResumptionEnabled(t *testing.T) {
	fingerprints := map[string]*utls.ClientHelloID{
		"chrome": &utls.HelloChrome_Auto,
		"edge":   &utls.HelloEdge_Auto,
	}
	versions := map[string]uint16{
		"TLS12": gotls.VersionTLS12,
		"TLS13": gotls.VersionTLS13,
	}

	for versionName, version := range versions {
		for fingerprintName, fingerprint := range fingerprints {
			t.Run(versionName+"/"+fingerprintName, func(t *testing.T) {
				t.Parallel()

				if !xraytls.SupportsSessionResumption(*fingerprint) {
					t.Fatalf("%s no longer qualifies for session resumption; "+
						"update this test together with the eligibility rule", fingerprintName)
				}

				states := runUClientHandshakes(
					t,
					[]*utls.ClientHelloID{fingerprint, fingerprint, fingerprint, fingerprint},
					version,
					false,
				)

				if states[0].DidResume {
					t.Fatal("first TLS connection unexpectedly resumed a session")
				}
				for connectionIndex, state := range states[1:] {
					if !state.DidResume {
						t.Fatalf("TLS connection %d did not resume the cached session", connectionIndex+2)
					}
				}
			})
		}
	}
}

// TestUClientSessionResumptionSkippedForIneligibleFingerprint pins the safe
// outcome for a preset that cannot resume without being rewritten: the
// connection still works, it simply performs a full handshake every time
// instead of shipping a forged ClientHello.
func TestUClientSessionResumptionSkippedForIneligibleFingerprint(t *testing.T) {
	if xraytls.SupportsSessionResumption(utls.HelloFirefox_148) {
		t.Skip("Firefox 148 now advertises the prerequisite extensions upstream")
	}

	states := runUClientHandshakes(
		t,
		[]*utls.ClientHelloID{&utls.HelloFirefox_148, &utls.HelloFirefox_148, &utls.HelloFirefox_148},
		gotls.VersionTLS13,
		false,
	)

	for i, state := range states {
		if state.DidResume {
			t.Fatalf("TLS connection %d resumed under a fingerprint that cannot carry a PSK", i+1)
		}
	}
}

func TestUClientSessionResumptionDisabled(t *testing.T) {
	for name, version := range map[string]uint16{
		"TLS12": gotls.VersionTLS12,
		"TLS13": gotls.VersionTLS13,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			states := runUClientHandshakes(
				t,
				[]*utls.ClientHelloID{&utls.HelloChrome_Auto, &utls.HelloChrome_Auto},
				version,
				true,
			)

			for i, state := range states {
				if state.DidResume {
					t.Fatalf("TLS connection %d resumed while session resumption was disabled", i+1)
				}
			}
		})
	}
}

// TestUClientSessionResumptionIsolatedByFingerprint proves a ticket learned
// under one fingerprint is never offered under another, even for the same SNI.
// Sharing one would be behavior no single browser process produces.
func TestUClientSessionResumptionIsolatedByFingerprint(t *testing.T) {
	states := runUClientHandshakes(
		t,
		[]*utls.ClientHelloID{
			&utls.HelloChrome_Auto,
			&utls.HelloEdge_Auto,
			&utls.HelloEdge_Auto,
		},
		gotls.VersionTLS13,
		false,
	)

	if states[1].DidResume {
		t.Fatal("Edge resumed a Chrome-fingerprint TLS session")
	}
	if !states[2].DidResume {
		t.Fatal("Edge did not resume its own TLS session")
	}
}

func runUClientHandshakes(
	t *testing.T,
	fingerprints []*utls.ClientHelloID,
	version uint16,
	sessionTicketsDisabled bool,
) []utls.ConnectionState {
	t.Helper()

	listener, serverErrors := startTLSServer(t, len(fingerprints), version)
	defer listener.Close()

	clientConfig := &gotls.Config{
		InsecureSkipVerify:     true,
		ServerName:             fmt.Sprintf("session-%d.test", sessionResumptionTestID.Add(1)),
		ClientSessionCache:     gotls.NewLRUClientSessionCache(1),
		SessionTicketsDisabled: sessionTicketsDisabled,
	}
	states := make([]utls.ConnectionState, 0, len(fingerprints))

	for i, fingerprint := range fingerprints {
		rawConn, err := stdnet.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatalf("dial TLS server for connection %d: %v", i+1, err)
		}
		if err := rawConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			rawConn.Close()
			t.Fatalf("set client deadline for connection %d: %v", i+1, err)
		}

		clientConn := xraytls.UClient(rawConn, clientConfig, fingerprint).(*xraytls.UConn)
		if err := clientConn.HandshakeContext(context.Background()); err != nil {
			clientConn.Close()
			t.Fatalf("handshake TLS connection %d: %v", i+1, err)
		}

		var marker [1]byte
		if _, err := io.ReadFull(clientConn, marker[:]); err != nil {
			clientConn.Close()
			t.Fatalf("read TLS marker on connection %d: %v", i+1, err)
		}
		if marker[0] != byte(i) {
			clientConn.Close()
			t.Fatalf("unexpected TLS marker on connection %d: got %d, want %d", i+1, marker[0], i)
		}

		states = append(states, clientConn.ConnectionState())
		if _, err := clientConn.Write([]byte{byte(i)}); err != nil {
			clientConn.Close()
			t.Fatalf("acknowledge TLS marker on connection %d: %v", i+1, err)
		}
		if err := clientConn.Close(); err != nil {
			t.Fatalf("close TLS connection %d: %v", i+1, err)
		}
	}

	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
	return states
}

func startTLSServer(t *testing.T, connections int, version uint16) (stdnet.Listener, <-chan error) {
	t.Helper()

	generatedCertificate, _ := cert.MustGenerate(
		nil,
		cert.CommonName("localhost"),
		cert.DNSNames("localhost"),
	)
	certificatePEM, privateKeyPEM := generatedCertificate.ToPEM()
	certificate, err := gotls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("parse generated TLS certificate: %v", err)
	}

	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for TLS test server: %v", err)
	}
	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{certificate},
		MinVersion:   version,
		MaxVersion:   version,
	}
	serverErrors := make(chan error, 1)
	go func() {
		defer close(serverErrors)
		for i := 0; i < connections; i++ {
			rawConn, err := listener.Accept()
			if err != nil {
				serverErrors <- fmt.Errorf("accept TLS connection %d: %w", i+1, err)
				return
			}
			if err := rawConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				rawConn.Close()
				serverErrors <- fmt.Errorf("set server deadline for connection %d: %w", i+1, err)
				return
			}

			serverConn := gotls.Server(rawConn, serverConfig)
			if err := serverConn.Handshake(); err != nil {
				serverConn.Close()
				serverErrors <- fmt.Errorf("handshake server connection %d: %w", i+1, err)
				return
			}
			if _, err := serverConn.Write([]byte{byte(i)}); err != nil {
				serverConn.Close()
				serverErrors <- fmt.Errorf("write TLS marker on connection %d: %w", i+1, err)
				return
			}

			var acknowledgment [1]byte
			if _, err := io.ReadFull(serverConn, acknowledgment[:]); err != nil {
				serverConn.Close()
				serverErrors <- fmt.Errorf("read TLS acknowledgment on connection %d: %w", i+1, err)
				return
			}
			if acknowledgment[0] != byte(i) {
				serverConn.Close()
				serverErrors <- fmt.Errorf(
					"unexpected TLS acknowledgment on connection %d: got %d, want %d",
					i+1,
					acknowledgment[0],
					i,
				)
				return
			}
			if err := serverConn.Close(); err != nil {
				serverErrors <- fmt.Errorf("close server connection %d: %w", i+1, err)
				return
			}
		}
		serverErrors <- nil
	}()

	return listener, serverErrors
}
