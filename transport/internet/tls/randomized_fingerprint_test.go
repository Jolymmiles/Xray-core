package tls_test

import (
	"context"
	gotls "crypto/tls"
	"io"
	stdnet "net"
	"slices"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// buildRandomizedHello builds the ClientHello Xray's TLS client sends with a
// randomized preset.
func buildRandomizedHello(t *testing.T, preset, seed string, nextProtos []string) *xraytls.UConn {
	t.Helper()
	client, server := stdnet.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	conn, err := xraytls.UClient(client, &gotls.Config{
		ServerName: "localhost",
		NextProtos: nextProtos,
	}, randomizedFingerprint(t, preset, seed))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// The randomized presets offer X25519MLKEM768 and send its key share first,
// then X25519's, as current browsers do. A key share outside supported_groups
// breaks RFC 8446, Section 4.2.8, and OpenSSL rejects it; the hybrid group
// without its key share makes a server that prefers it ask again, which the
// uTLS client cannot answer, and makes REALITY turn the hello away. There is
// no P-256 key share: X25519MLKEM768 and X25519 with keys of their own is what
// Chrome sends, while three key shares with keys of their own match no
// browser.
func TestRandomizedFingerprintKeyShares(t *testing.T) {
	for _, preset := range randomizedPresets {
		for _, seed := range randomizedSeeds {
			t.Run(preset+"/"+seed.name, func(t *testing.T) {
				hello := buildRandomizedHello(t, preset, seed.seed, nil).HandshakeState.Hello
				var groups []utls.CurveID
				for _, share := range hello.KeyShares {
					groups = append(groups, share.Group)
					if !slices.Contains(hello.SupportedCurves, share.Group) {
						t.Errorf("key share for %v is not offered in supported_groups %v", share.Group, hello.SupportedCurves)
					}
				}
				if !slices.Equal(groups, []utls.CurveID{utls.X25519MLKEM768, utls.X25519}) {
					t.Fatalf("key shares are for %v, want [X25519MLKEM768 X25519]", groups)
				}
				if len(hello.KeyShares[0].Data) != 1216 || len(hello.KeyShares[1].Data) != 32 {
					t.Fatalf("key share sizes are %d and %d, want 1216 and 32", len(hello.KeyShares[0].Data), len(hello.KeyShares[1].Data))
				}
			})
		}
	}
}

// Whatever changes the key shares must leave the configured ALPN alone.
func TestRandomizedFingerprintKeepsConfiguredALPN(t *testing.T) {
	for _, preset := range randomizedPresets {
		for _, seed := range randomizedSeeds {
			t.Run(preset+"/"+seed.name, func(t *testing.T) {
				conn := buildRandomizedHello(t, preset, seed.seed, []string{"http/1.1"})
				var protocols []string
				found := false
				for _, extension := range conn.Extensions {
					if alpn, ok := extension.(*utls.ALPNExtension); ok {
						found = true
						protocols = alpn.AlpnProtocols
					}
				}
				switch {
				case preset == "randomizednoalpn" && found:
					t.Fatalf("randomizednoalpn sends ALPN %v", protocols)
				case preset == "randomized" && !slices.Equal(protocols, []string{"http/1.1"}):
					t.Fatalf("ALPN is %v, want [http/1.1]", protocols)
				}
			})
		}
	}
}

type groupServerResult struct {
	retried bool
	group   gotls.CurveID
	err     error
}

// startGroupServer runs a TLS 1.3 server that supports groups only. Go's
// server prefers a post-quantum group to any other, even at the cost of a
// HelloRetryRequest, and otherwise a group the client sent a key share for.
func startGroupServer(t *testing.T, groups []gotls.CurveID) (address string, result <-chan groupServerResult) {
	t.Helper()
	generated, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certificate, err := gotls.X509KeyPair(generated.ToPEM())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates:     []gotls.Certificate{certificate},
		MinVersion:       gotls.VersionTLS13,
		CurvePreferences: groups,
	})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan groupServerResult, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			results <- groupServerResult{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		tlsConn := conn.(*gotls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			results <- groupServerResult{err: err}
			return
		}
		state := tlsConn.ConnectionState()
		results <- groupServerResult{retried: state.HelloRetryRequest, group: state.CurveID}
		_, _ = io.Copy(tlsConn, tlsConn)
	}()
	return listener.Addr().String(), results
}

// handshakeRandomized dials address with a randomized preset, proves the
// session carries data, and returns what the server saw.
func handshakeRandomized(t *testing.T, address, preset, seed string, result <-chan groupServerResult) groupServerResult {
	t.Helper()
	rawConn, err := stdnet.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// ClientHandshake closes rawConn when it fails, so the server is not left
	// waiting for a flight that never comes.
	conn, clientErr := xraytls.ClientHandshake(ctx, rawConn, &gotls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}, randomizedFingerprint(t, preset, seed))
	var server groupServerResult
	select {
	case server = <-result:
	case <-time.After(5 * time.Second):
		t.Fatalf("server did not finish its handshake; client: %v", clientErr)
	}
	if clientErr != nil || server.err != nil {
		t.Fatalf("handshake: client %v, server %v", clientErr, server.err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var echo [1]byte
	if _, err := io.ReadFull(conn, echo[:]); err != nil || echo[0] != 42 {
		t.Fatalf("echo = %v, %v", echo, err)
	}
	return server
}

func TestRandomizedFingerprintHandshakesWithPostQuantumServer(t *testing.T) {
	for _, preset := range randomizedPresets {
		for _, seed := range randomizedSeeds {
			t.Run(preset+"/"+seed.name, func(t *testing.T) {
				address, result := startGroupServer(t, []gotls.CurveID{gotls.X25519MLKEM768, gotls.X25519, gotls.CurveP256, gotls.CurveP384})
				server := handshakeRandomized(t, address, preset, seed.seed, result)
				// The hello carries the key share this server wants, so it
				// needs no second round trip.
				if server.group != gotls.X25519MLKEM768 || server.retried {
					t.Fatalf("server selected %v, HelloRetryRequest %v; want X25519MLKEM768 without one", server.group, server.retried)
				}
			})
		}
	}
}

// A server that supports P-256 alone asks for its key share again, which is
// legal and works.
func TestRandomizedFingerprintHandshakesWithP256Server(t *testing.T) {
	for _, preset := range randomizedPresets {
		for _, seed := range randomizedSeeds {
			t.Run(preset+"/"+seed.name, func(t *testing.T) {
				address, result := startGroupServer(t, []gotls.CurveID{gotls.CurveP256})
				if server := handshakeRandomized(t, address, preset, seed.seed, result); server.group != gotls.CurveP256 {
					t.Fatalf("server selected %v, want P-256", server.group)
				}
			})
		}
	}
}
