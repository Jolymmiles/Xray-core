package reality

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
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

// pythonSSLCheck exits 77 when the interpreter cannot run opensslServerPy:
// Python 2, no ssl module, or an OpenSSL without TLS 1.3 or ALPN.
const pythonSSLCheck = `import sys
if sys.version_info[0] < 3:
    raise SystemExit(77)
try:
    import ssl
except ImportError:
    raise SystemExit(77)
if not getattr(ssl, "HAS_TLSv1_3", False) or not getattr(ssl, "HAS_ALPN", False):
    raise SystemExit(77)
`

func pythonWithSSL(t *testing.T) string {
	t.Helper()
	var failure string
	for _, name := range []string{"python3", "python"} {
		bin, err := exec.LookPath(name)
		if err != nil || strings.Contains(strings.ToLower(filepath.ToSlash(bin)), "/microsoft/windowsapps/") {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := exec.CommandContext(ctx, bin, "-c", pythonSSLCheck).CombinedOutput()
		cancel()
		if err == nil {
			return bin
		}
		if status, ok := err.(*exec.ExitError); !ok || status.ExitCode() != 77 {
			failure = fmt.Sprintf("%s: %v: %s", bin, err, output)
		}
	}
	if failure != "" {
		t.Fatalf("Python ssl availability check: %s", failure)
	}
	t.Skip("no Python interpreter with ssl is installed")
	return ""
}

// opensslTarget serves TLS with OpenSSL, as nginx does.
func opensslTarget(t *testing.T, args ...string) string {
	t.Helper()
	bin := pythonWithSSL(t)
	dir := t.TempDir()
	certPEM, keyPEM := testCertificate(t, "example.com")
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"-c", opensslServerPy, certFile, keyFile}, args...)...)
	stderr, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	cmd.Stderr = stderr
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
	type readiness struct {
		port int
		err  error
	}
	ready := make(chan readiness, 1)
	go func() {
		var result readiness
		_, result.err = fmt.Fscan(stdout, &result.port)
		ready <- result
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case result := <-ready:
		if result.err != nil || result.port < 1 || result.port > 65535 {
			output, _ := os.ReadFile(stderr.Name())
			t.Fatalf("OpenSSL fixture reported port %d: %v: %s", result.port, result.err, output)
		}
		return "127.0.0.1:" + strconv.Itoa(result.port)
	case <-timer.C:
		output, _ := os.ReadFile(stderr.Name())
		t.Fatalf("OpenSSL fixture readiness timed out: %s", output)
		return ""
	}
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
	if reply := probeBadBinder(config, "example.com", 2, shape.badBinderSession); reply.kind != alertRefusal || reply.delay != 0 || !bytes.Equal(reply.alerts, decryptErrorAlert) {
		t.Fatalf("crypto/tls refuses a wrong binder with decrypt_error at once: %+v", reply)
	}
	if shape.HelloDelta != 6 || shape.Lifetime != 7*24*3600 {
		t.Fatalf("ServerHello delta %d, lifetime %d", shape.HelloDelta, shape.Lifetime)
	}
	if len(shape.Prefix) > 2 {
		t.Fatalf("crypto/tls tickets start with a random IV, prefix %x", shape.Prefix)
	}
}

func TestTicketProbeVerifiesDestinationName(t *testing.T) {
	config := &Config{Type: "tcp", Dest: goTarget(t)}
	_, err := probeOnce(config, "different.example", 2, nil)
	var hostname x509.HostnameError
	if !errors.As(err, &hostname) {
		t.Fatalf("ticket probe for a different server name: %v, want a hostname error", err)
	}
	if _, err := probeOnce(config, "example.com", 2, nil); err != nil {
		t.Fatalf("ticket probe for the certificate's name: %v", err)
	}
}

type probeBytesConn struct {
	net.Conn
	io.Reader
}

func (c probeBytesConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

func TestProbeCaptureByteLimit(t *testing.T) {
	capture := &probeCaptureConn{Conn: probeBytesConn{Reader: bytes.NewReader(make([]byte, maxProbeBytes+512))}}
	n, err := io.Copy(io.Discard, capture)
	if n != maxProbeBytes || !errors.Is(err, errProbeLimit) || len(capture.received()) != maxProbeBytes {
		t.Fatalf("read %d bytes with error %v, want limit at %d", n, err, maxProbeBytes)
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
	reply := probeBadBinder(config, "example.com", 2, shape.badBinderSession)
	illegalParameter := []byte{21, 3, 3, 0, 2, 2, 47}
	if reply.kind != alertRefusal || reply.delay != 0 ||
		(!bytes.Equal(reply.alerts, decryptErrorAlert) && !bytes.Equal(reply.alerts, illegalParameter)) {
		t.Fatalf("OpenSSL must refuse a wrong binder with an immediate fatal alert: %+v", reply)
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
	config := &Config{Type: "tcp", Dest: ln.Addr().String()}
	shape, err := probeTicketShape(config, "example.com", 0)
	if !errors.Is(err, errNoTargetTickets) || shape != nil {
		t.Fatalf("a target without tickets has no shape: %+v", shape)
	}
	old := time.Now().Add(-2 * ticketShapeRefresh)
	for _, tc := range []struct {
		name        string
		previous    TicketShape
		keepsIssuer bool
		unknown     bool
	}{
		// Three seconds without a ticket do not prove that a destination
		// which issued tickets stopped: it may send them later.
		{"issuing", TicketShape{Issues: true}, true, false},
		// An expired issuer has shown only inconclusive samples: unknown.
		{"issuing_failed_long_ago", TicketShape{Issues: true, failedSince: time.Now().Add(-ticketShapeMaxAge)}, false, true},
		{"ticketless", TicketShape{noTickets: true}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := config.Dest + " " + t.Name()
			previous := tc.previous
			previous.probed = old
			GlobalTicketShapes.Store(key, &previous)
			t.Cleanup(func() { GlobalTicketShapes.Delete(key) })
			RefreshTicketShape(config, key, "example.com", 0)
			for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				value, _ := GlobalTicketShapes.Load(key)
				fresh := value.(*TicketShape)
				if !fresh.probed.After(old) {
					continue
				}
				if tc.keepsIssuer {
					if LoadTicketShape(key) == nil || fresh.failedSince.IsZero() {
						t.Fatalf("a ticketless refresh replaced an issuing profile: %+v", fresh)
					}
					return
				}
				if LoadTicketShape(key) != nil {
					t.Fatal("refresh retained a ticket shape after a confirmed no-ticket handshake")
				}
				if tc.unknown {
					if loadTicketProfile(key) != nil {
						t.Fatalf("an expired issuer became a confirmed ticketless profile: %+v", fresh)
					}
					return
				}
				if profile := loadTicketProfile(key); profile == nil || !profile.noTickets {
					t.Fatal("a successful ticketless measurement was indistinguishable from a failed probe")
				}
				return
			}
			t.Fatal("ticket shape refresh did not finish")
		})
	}
}

// A refresh publishes the fresh shape before its bad-binder probe ends, which
// takes up to 80 s for a silent destination. Until then the previous refusal
// still describes the destination; a refusal probe that measures nothing
// leaves it, and one that measures replaces it.
func TestRefreshKeepsRefusalWhileProbing(t *testing.T) {
	for _, measured := range []bool{false, true} {
		t.Run(fmt.Sprint("measured=", measured), func(t *testing.T) {
			dest := goTarget(t)
			release := make(chan struct{})
			var dials atomic.Int32
			config := &Config{Type: "tcp", Dest: dest, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if dials.Add(1) <= 2 { // the full and the resumed probe
					return new(net.Dialer).DialContext(ctx, network, address)
				}
				<-release
				if measured {
					return new(net.Dialer).DialContext(ctx, network, address)
				}
				return nil, net.ErrClosed
			}}
			key := dest + " refusal"
			t.Cleanup(func() { GlobalTicketShapes.Delete(key) })
			old := time.Now().Add(-2 * ticketShapeRefresh)
			alert := []byte{21, 3, 3, 0, 2, 2, 40}
			GlobalTicketShapes.Store(key, &TicketShape{
				Issues: true, Resumes: true, probed: old,
				RefusesBadBinder: true, BadBinder: alert, BadBinderDelay: time.Second, badBinderClose: alertRefusal,
			})
			RefreshTicketShape(config, key, "example.com", 0)
			load := func() *TicketShape {
				value, _ := GlobalTicketShapes.Load(key)
				return value.(*TicketShape)
			}
			for deadline := time.Now().Add(15 * time.Second); dials.Load() < 3; time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					close(release)
					t.Fatal("the refresh did not start its bad-binder probe")
				}
			}
			fresh := load()
			close(release)
			if !fresh.probed.After(old) || !fresh.RefusesBadBinder || !bytes.Equal(fresh.BadBinder, alert) ||
				fresh.BadBinderDelay != time.Second || fresh.badBinderClose != alertRefusal {
				t.Fatalf("fresh shape lost the refusal while its probe runs: %+v", fresh)
			}
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				final := load()
				if final == fresh {
					continue
				}
				want := alert
				if measured {
					want = decryptErrorAlert // crypto/tls refuses at once
				}
				if final.badBinderSession != nil || !final.RefusesBadBinder || !bytes.Equal(final.BadBinder, want) {
					t.Fatalf("refusal after the probe %+v, want alert % x", final, want)
				}
				return
			}
			t.Fatal("the result of the refusal probe was not published")
		})
	}
}

// The ClientHello eofAfterHello read: not read or not parsed, without a
// ticket, or offering one.
const (
	helloUnread = iota
	helloWithoutTicket
	helloWithTicket
)

// eofAfterHello accepts one connection, reads one TLS record and closes,
// reporting what that record was.
func eofAfterHello(t *testing.T) (dest string, offered <-chan int) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	result := make(chan int, 1)
	go func() {
		defer close(result) // helloUnread
		peer, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		defer peer.Close()
		if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return
		}
		record := make([]byte, recordHeaderLen)
		if _, err := io.ReadFull(peer, record); err != nil {
			return
		}
		record = append(record, make([]byte, int(record[3])<<8|int(record[4]))...)
		if _, err := io.ReadFull(peer, record[recordHeaderLen:]); err != nil {
			return
		}
		var hello clientHelloMsg
		switch {
		case !hello.unmarshal(record[recordHeaderLen:]):
		case len(hello.pskIdentities) != 0:
			result <- helloWithTicket
		default:
			result <- helloWithoutTicket
		}
	}()
	return listener.Addr().String(), result
}

func TestProbePeerEOFIsFIN(t *testing.T) {
	full, err := probeOnce(&Config{Type: "tcp", Dest: goTarget(t)}, "example.com", 0, nil)
	if err != nil || len(full.sessions) == 0 {
		t.Fatalf("no ticket from the fixture: %v", err)
	}
	dest, offered := eofAfterHello(t)
	config := &Config{Type: "tcp4", Dest: dest}
	if reply := probeBadBinder(config, "example.com", 0, full.sessions[0]); reply.kind != finRefusal || len(reply.alerts) != 0 || reply.delay >= time.Second {
		t.Fatalf("early EOF classified as %+v, want FIN within a second", reply)
	}
	if got := <-offered; got != helloWithTicket {
		t.Fatalf("the peer read ClientHello kind %d, want one offering the ticket", got)
	}
}

// A ClientHello without pre_shared_key tests no binder: whatever the
// destination answers to it is not its bad-binder refusal.
func TestProbeWithoutTicketIsNoRefusal(t *testing.T) {
	dest, offered := eofAfterHello(t)
	config := &Config{Type: "tcp4", Dest: dest}
	if reply := probeBadBinder(config, "example.com", 0, nil); reply.kind != noRefusal {
		t.Fatalf("a probe without a ticket published refusal %+v", reply)
	}
	if got := <-offered; got != helloWithoutTicket {
		t.Fatalf("the peer read ClientHello kind %d, want a parsed one without a ticket", got)
	}
}

func TestTicketShapeExpiresAfterFailedRefresh(t *testing.T) {
	config := &Config{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, net.ErrClosed
	}}
	for _, tc := range []struct {
		name    string
		failure time.Duration
		keeps   bool
	}{
		{"healthy_after_idle", 0, true},
		{"recent_failure", 2 * ticketShapeRefresh, true},
		{"expired", ticketShapeMaxAge + time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := t.Name()
			t.Cleanup(func() { GlobalTicketShapes.Delete(key) })
			old := time.Now().Add(-2 * ticketShapeMaxAge)
			var failedSince time.Time
			if tc.failure != 0 {
				failedSince = time.Now().Add(-tc.failure)
			}
			GlobalTicketShapes.Store(key, &TicketShape{Issues: true, probed: old, failedSince: failedSince})
			if (LoadTicketShape(key) != nil) != tc.keeps {
				t.Fatal("unexpected profile availability before refresh")
			}
			RefreshTicketShape(config, key, "example.com", 0)
			for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				value, _ := GlobalTicketShapes.Load(key)
				fresh := value.(*TicketShape)
				if fresh.probed.Equal(old) {
					continue
				}
				if fresh.Issues != tc.keeps || (tc.keeps && fresh.failedSince.IsZero()) ||
					(tc.keeps && !failedSince.IsZero() && fresh.failedSince != failedSince) {
					t.Fatalf("failed refresh changed the profile incorrectly: %+v", fresh)
				}
				return
			}
			t.Fatal("ticket shape refresh did not finish")
		})
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
	if val, _ := GlobalTicketShapes.Load(key); val.(*TicketShape).probed != old.probed {
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
