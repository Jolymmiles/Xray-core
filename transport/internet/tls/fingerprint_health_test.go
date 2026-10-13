package tls_test

import (
	"context"
	gotls "crypto/tls"
	"io"
	stdnet "net"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// healthServers are the key exchange preferences a server may have.
var healthServers = map[string][]gotls.CurveID{
	"post-quantum": {gotls.X25519MLKEM768, gotls.X25519, gotls.CurveP256, gotls.CurveP384},
	"x25519":       {gotls.X25519},
	"p256":         {gotls.CurveP256},
}

// knownFingerprintDefects lists, by fingerprint and server, the handshakes
// that fail today and how. A defect that disappears, or a failure that is not
// listed, fails the test: update the list with the change that explains it.
var knownFingerprintDefects = map[string]string{
	// The preset is 360 Browser 7.5, which offers no X25519.
	"360/x25519": "handshake failure",
}

// healthFingerprints are the fingerprints a configuration usually names: the
// presets, and the Modern ones "random" draws from.
func healthFingerprints(t *testing.T) map[string]*utls.ClientHelloID {
	t.Helper()
	fingerprints := make(map[string]*utls.ClientHelloID)
	for name, id := range xraytls.ModernFingerprints {
		fingerprints[name] = id
	}
	for name, id := range xraytls.PresetFingerprints {
		switch name {
		case "unsafe", "random":
		case "randomized", "randomizednoalpn":
			for _, seed := range randomizedSeeds {
				fingerprints[name+"@"+seed.seed[:8]] = randomizedFingerprint(t, name, seed.seed)
			}
		default:
			fingerprints[name] = id
		}
	}
	return fingerprints
}

// healthHandshake completes a handshake and one byte each way with a server
// that supports groups only.
func healthHandshake(t *testing.T, fingerprint *utls.ClientHelloID, groups []gotls.CurveID, certificate gotls.Certificate) error {
	t.Helper()
	listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates:     []gotls.Certificate{certificate},
		CurvePreferences: groups,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	// Runs last, after the client has closed its connection.
	defer func() {
		_ = listener.Close()
		<-done
	}()
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(conn, conn)
	}()
	rawConn, err := stdnet.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := xraytls.ClientHandshake(context.Background(), rawConn, &gotls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}, fingerprint)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{1}); err != nil {
		return err
	}
	_, err = io.ReadFull(conn, make([]byte, 1))
	return err
}

// TestFingerprintHealth sends the hello of every commonly named fingerprint
// to servers with different key exchange preferences.
func TestFingerprintHealth(t *testing.T) {
	generated, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certificate, err := gotls.X509KeyPair(generated.ToPEM())
	if err != nil {
		t.Fatal(err)
	}
	fingerprints := healthFingerprints(t)
	names := make([]string, 0, len(fingerprints))
	for name := range fingerprints {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]bool)
	for _, name := range names {
		t.Run(name+"/hello", func(t *testing.T) {
			client, server := stdnet.Pipe()
			defer client.Close()
			defer server.Close()
			conn, err := xraytls.UClient(client, &gotls.Config{ServerName: "localhost"}, fingerprints[name])
			if err != nil {
				t.Fatal(err)
			}
			hello := conn.HandshakeState.Hello
			var shares []utls.CurveID
			for _, share := range hello.KeyShares {
				if slices.Contains(shares, share.Group) {
					t.Errorf("two key shares for %v", share.Group)
				}
				shares = append(shares, share.Group)
				// RFC 8446, Section 4.2.8.
				if !slices.Contains(hello.SupportedCurves, share.Group) {
					t.Errorf("key share for %v is not offered in supported_groups %v", share.Group, hello.SupportedCurves)
				}
			}
		})
		for server, groups := range healthServers {
			cell := name + "/" + server
			t.Run(cell, func(t *testing.T) {
				seen[cell] = true
				err := healthHandshake(t, fingerprints[name], groups, certificate)
				want, known := knownFingerprintDefects[cell]
				switch {
				case err == nil && known:
					t.Fatalf("known defect %q no longer happens; update knownFingerprintDefects", want)
				case err != nil && !known:
					t.Fatalf("handshake: %v", err)
				case err != nil && !strings.Contains(err.Error(), want):
					t.Fatalf("handshake fails with %v, known defect is %q", err, want)
				}
			})
		}
	}
	for cell := range knownFingerprintDefects {
		if !seen[cell] {
			t.Errorf("known defect %s names no tested fingerprint and server", cell)
		}
	}
}
