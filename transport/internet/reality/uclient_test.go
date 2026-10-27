package reality

import (
	"context"
	"crypto/ecdh"
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

// closeRecorder reports whether the connection it wraps was closed.
type closeRecorder struct {
	stdnet.Conn
	closed atomic.Bool
}

func (c *closeRecorder) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// startEchoREALITYServer runs a REALITY server in front of a cover target
// that echoes what an authenticated client sends.
func startEchoREALITYServer(t *testing.T, mldsa65Seed []byte) (address string, publicKey []byte) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// REALITY pads its certificate record to the cover's. An ML-DSA-65
	// signature makes it about 3.5 KB, more than a bare test certificate.
	var names []string
	for i := range 200 {
		names = append(names, fmt.Sprintf("name-%03d.%s", i, keyShareTestServerName))
	}
	cover, _ := startCoverTarget(t, cert.DNSNames(names...))
	serverConfig := (&Config{
		Dest:        cover,
		Type:        "tcp",
		ServerNames: []string{keyShareTestServerName},
		PrivateKey:  privateKey.Bytes(),
		ShortIds:    [][]byte{{1, 2, 3, 4, 5, 6, 7, 8}},
		Mldsa65Seed: mldsa65Seed,
	}).GetREALITYConfig()
	detectCoverRecords(t, serverConfig)
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		realityConn, err := Server(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		defer realityConn.Close()
		_, _ = io.Copy(realityConn, realityConn)
	}()
	return listener.Addr().String(), privateKey.PublicKey().Bytes()
}

func dialUClient(t *testing.T, address string, config *Config) (stdnet.Conn, *closeRecorder, error) {
	t.Helper()
	dialed, err := stdnet.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	raw := &closeRecorder{Conn: dialed}
	t.Cleanup(func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := UClient(raw, config, ctx, net.TCPDestination(net.DomainAddress(keyShareTestServerName), 443))
	return conn, raw, err
}

// UClient authenticates the server, ML-DSA-65 signature included when the
// client is given its key, and carries data both ways.
func TestREALITYUClientEcho(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	verifyKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string]struct{ seed, verify []byte }{
		"x25519":                {},
		"ml-dsa-65":             {seed: seed, verify: verifyKey.PublicKey().Bytes()},
		"server ml-dsa-65 only": {seed: seed},
	} {
		t.Run(name, func(t *testing.T) {
			address, publicKey := startEchoREALITYServer(t, keys.seed)
			conn, raw, err := dialUClient(t, address, &Config{
				Fingerprint:   "chrome",
				ServerName:    keyShareTestServerName,
				PublicKey:     publicKey,
				ShortId:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
				Mldsa65Verify: keys.verify,
			})
			if err != nil {
				t.Fatal(err)
			}
			if raw.closed.Load() {
				t.Fatal("UClient closed the connection it returned")
			}
			if !conn.(*UConn).Verified {
				t.Fatal("server not verified")
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			echo := make([]byte, 4)
			if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "ping" {
				t.Fatalf("echo %q, %v", echo, err)
			}
		})
	}
}

// A failed dial leaves no open connection behind, whatever failed.
func TestREALITYUClientClosesOnFailure(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	otherSeed := make([]byte, 32)
	if _, err := rand.Read(otherSeed); err != nil {
		t.Fatal(err)
	}
	wrongKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]func(publicKey []byte) *Config{
		"unknown fingerprint": func(publicKey []byte) *Config {
			return &Config{Fingerprint: "no-such-fingerprint", ServerName: keyShareTestServerName, PublicKey: publicKey}
		},
		"fingerprint without a ClientHello to seal": func(publicKey []byte) *Config {
			return &Config{Fingerprint: "hellochrome_100_psk", ServerName: keyShareTestServerName, PublicKey: publicKey}
		},
		"invalid public key": func([]byte) *Config {
			return &Config{Fingerprint: "chrome", ServerName: keyShareTestServerName, PublicKey: []byte{1}}
		},
		"wrong ML-DSA-65 key": func(publicKey []byte) *Config {
			return &Config{
				Fingerprint:   "chrome",
				ServerName:    keyShareTestServerName,
				PublicKey:     publicKey,
				ShortId:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
				Mldsa65Verify: wrongKey.PublicKey().Bytes(),
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			address, publicKey := startEchoREALITYServer(t, seed)
			conn, raw, err := dialUClient(t, address, config(publicKey))
			if err == nil {
				conn.Close()
				t.Fatal("UClient succeeded")
			}
			if !raw.closed.Load() {
				t.Fatalf("UClient failed with %v and left the connection open", err)
			}
		})
	}
}
