package reality

import (
	"bytes"
	"fmt"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func testCertificate(t *testing.T, name string) (certPEM, keyPEM []byte) {
	t.Helper()
	return testCertPEM, testKeyPEM
}

var testCertPEM, testKeyPEM []byte

// TestMain makes the test certificate trusted, as a real target's is: the
// probe of the target's records verifies it.
func TestMain(m *testing.M) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	testCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	testKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir, err := os.MkdirTemp("", "reality-test")
	if err != nil {
		panic(err)
	}
	certFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certFile, testCertPEM, 0o600); err != nil {
		panic(err)
	}
	os.Setenv("SSL_CERT_FILE", certFile)
	os.Unsetenv("SSL_CERT_DIR")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// goTarget serves TLS with crypto/tls, as Caddy does: one ticket, sent with
// the server's first flight.
func goTarget(t *testing.T) string {
	t.Helper()
	certPEM, keyPEM := testCertificate(t, "example.com")
	cert, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// opensslServerPy is a threaded TLS server on Python's ssl module, which is
// OpenSSL: two tickets after a full handshake, one after a resumed one, both
// after the client's Finished, as nginx sends them. openssl s_server would
// do, but it serves one connection at a time.
const opensslServerPy = `
import socket, ssl, sys, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
ctx.set_alpn_protocols(["h2", "http/1.1"])
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(64)
print(srv.getsockname()[1], flush=True)
def serve(c):
    try:
        s = ctx.wrap_socket(c, server_side=True)
        while s.recv(4096):
            pass
    except Exception:
        pass
    finally:
        c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
`

// opensslTarget serves TLS with OpenSSL, as nginx does.
func opensslTarget(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	dir := t.TempDir()
	certPEM, keyPEM := testCertificate(t, "example.com")
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-c", opensslServerPy, certFile, keyFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	var port int
	if _, err := fmt.Fscan(stdout, &port); err != nil {
		t.Skip("python3 has no ssl module: ", err)
	}
	return "127.0.0.1:" + strconv.Itoa(port)
}

func TestProbeTicketShapeGoTarget(t *testing.T) {
	config := &Config{Type: "tcp", Dest: goTarget(t)}
	shape, err := probeTicketShape(config, "example.com", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", shape)
	if !shape.Resumes || shape.Tickets != 1 || shape.ResTickets != 1 {
		t.Fatalf("crypto/tls issues one ticket per handshake: %+v", shape)
	}
	if answer, delay, ok := probeBadBinder(config, "example.com", 2, shape.badBinderSession); !ok || delay != 0 || !bytes.Equal(answer, decryptErrorAlert) {
		t.Fatalf("crypto/tls refuses a wrong binder with decrypt_error at once: %x after %v", answer, delay)
	}
	if shape.HelloDelta != 6 || shape.Lifetime != 7*24*3600 {
		t.Fatalf("ServerHello delta %d, lifetime %d", shape.HelloDelta, shape.Lifetime)
	}
	if len(shape.Prefix) > 2 {
		t.Fatalf("crypto/tls tickets start with a random IV, prefix %x", shape.Prefix)
	}
}

func TestProbeTicketShapeOpenSSLTarget(t *testing.T) {
	config := &Config{Type: "tcp", Dest: opensslTarget(t)}
	shape, err := probeTicketShape(config, "example.com", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", shape)
	if !shape.Resumes || shape.Tickets != 2 || shape.ResTickets != 1 {
		t.Fatalf("OpenSSL issues two tickets, one after resumption: %+v", shape)
	}
	if shape.HelloDelta != 6 {
		t.Fatalf("ServerHello delta %d", shape.HelloDelta)
	}
	if answer, delay, ok := probeBadBinder(config, "example.com", 2, shape.badBinderSession); !ok || delay != 0 || !bytes.Equal(answer, decryptErrorAlert) {
		t.Fatalf("OpenSSL refuses a wrong binder with decrypt_error at once: %x after %v", answer, delay)
	}
	if len(shape.Prefix) < 16 {
		t.Fatalf("OpenSSL tickets start with a 16-byte key name, prefix %x", shape.Prefix)
	}
}

func TestProbeTicketShapeNoTickets(t *testing.T) {
	certPEM, keyPEM := testCertificate(t, "example.com")
	cert, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates:           []gotls.Certificate{cert},
		SessionTicketsDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	shape, err := probeTicketShape(&Config{Type: "tcp", Dest: ln.Addr().String()}, "example.com", 0)
	if err == nil || shape != nil {
		t.Fatalf("a target without tickets has no shape: %+v", shape)
	}
}

func TestTicketShapeIsProbedAgain(t *testing.T) {
	config := &Config{Type: "tcp", Dest: goTarget(t)}
	key := config.Dest + " example.com 2"
	DetectTicketShape(config, key, "example.com", 2)
	waitShape := func(after time.Time) *TicketShape {
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if val, _ := GlobalTicketShapes.Load(key); val != nil {
				if shape, ok := val.(*TicketShape); ok && shape.probed.After(after) {
					return shape
				}
			}
		}
		t.Fatal("no shape probed")
		return nil
	}
	old := waitShape(time.Time{})
	RefreshTicketShape(config, key, "example.com", 2)
	if val, _ := GlobalTicketShapes.Load(key); val != old {
		t.Fatal("a fresh shape is not probed again")
	}
	stale := *old
	stale.probed = time.Now().Add(-2 * ticketShapeRefresh)
	GlobalTicketShapes.Store(key, &stale)
	start := time.Now()
	RefreshTicketShape(config, key, "example.com", 2)
	if fresh := waitShape(start); !fresh.Resumes {
		t.Fatal("the target resumes")
	}
}

// decryptErrorAlert is a plaintext TLS alert record: fatal, decrypt_error.
var decryptErrorAlert = []byte{21, 3, 3, 0, 2, 2, 51}
