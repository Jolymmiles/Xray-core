package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	gonet "net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/net"
)

const testServerName = "example.com"

func testCertificate(t *testing.T) (certPEM, keyPEM []byte) {
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

// goTarget is a crypto/tls site, as Caddy serves.
func goTarget(t *testing.T) string {
	t.Helper()
	certPEM, keyPEM := testCertificate(t)
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
if len(sys.argv) > 3 and sys.argv[3] == "stateful":
    # sessions in the server's cache, tickets only their ids: nginx with
    # ssl_session_tickets off, as Mozilla's settings have it
    ctx.options |= ssl.OP_NO_TICKET
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
func opensslTarget(t *testing.T, args ...string) string {
	t.Helper()
	bin, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	dir := t.TempDir()
	certPEM, keyPEM := testCertificate(t)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"-c", opensslServerPy, certFile, keyFile}, args...)...)
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

type realityServer struct {
	addr   string
	config *reality.Config
	public []byte
}

// startRealityServer runs a REALITY server for target that echoes what
// verified clients send, once it knows the target's records and tickets.
func startRealityServer(t *testing.T, target string) *realityServer {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := (&Config{
		Type:        "tcp",
		Dest:        target,
		ServerNames: []string{testServerName},
		PrivateKey:  priv.Bytes(),
		ShortIds:    [][]byte{make([]byte, 8)},
		Browser:     "auto",
	}).GetREALITYConfig()
	config.Show = os.Getenv("REALITY_SHOW") != ""
	reality.DetectPostHandshakeRecordsLens(config)
	// The client's ClientHello offers h2 and http/1.1, as Chrome's does.
	key := target + " " + testServerName + " 2"
	reality.DetectTicketShape(config, key, testServerName, 2)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		_, recordsOK := reality.GlobalPostHandshakeRecordsLens.Load(key)
		if val, _ := reality.GlobalPostHandshakeRecordsLens.Load(key); recordsOK {
			_, recordsOK = val.([]int)
		}
		_, shapeProbed := reality.GlobalTicketShapes.Load(key)
		if val, _ := reality.GlobalTicketShapes.Load(key); shapeProbed {
			_, shapeProbed = val.(*reality.TicketShape)
		}
		// Targets that resume are probed with a wrong binder afterwards.
		if shape := reality.LoadTicketShape(key); shape != nil && shape.Resumes && !shape.RefusesBadBinder {
			shapeProbed = false
		}
		if recordsOK && shapeProbed {
			val, _ := reality.GlobalPostHandshakeRecordsLens.Load(key)
			t.Logf("target records after the handshake %v, tickets %+v", val, reality.LoadTicketShape(key))
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the target's records and tickets were not probed")
		}
	}

	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
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
				server, err := reality.Server(context.Background(), conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				io.Copy(server, server)
			}()
		}
	}()
	return &realityServer{addr: ln.Addr().String(), config: config, public: priv.PublicKey().Bytes()}
}

// recordCapture keeps the record lengths the server sends.
type recordCapture struct {
	gonet.Conn
	mu  sync.Mutex
	in  []byte
	out []byte
	// spoilBinder flips the last byte of the ClientHello: its binder.
	spoilBinder bool
}

func (c *recordCapture) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.spoilBinder && len(c.out) == 0 {
		b = bytes.Clone(b)
		b[len(b)-1] ^= 1
	}
	c.out = append(c.out, b...)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recordCapture) received() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.in)
}

// helloExtensions returns the extension types of the ClientHello sent.
func (c *recordCapture) helloExtensions() []uint16 {
	types, _ := c.helloExtensionLens()
	return types
}

// helloExtensionLens returns the extension types of the ClientHello sent and
// their lengths.
func (c *recordCapture) helloExtensionLens() ([]uint16, []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.out[5:] // record header
	p := 4 + 2 + 32
	p += 1 + int(b[p])
	p += 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 1 + int(b[p])
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	var types []uint16
	var lens []int
	for p += 2; p < end; p += 4 + int(binary.BigEndian.Uint16(b[p+2:])) {
		types = append(types, binary.BigEndian.Uint16(b[p:]))
		lens = append(lens, int(binary.BigEndian.Uint16(b[p+2:])))
	}
	return types, lens
}

func (c *recordCapture) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.in = append(c.in, b[:n]...)
	c.mu.Unlock()
	return n, err
}

func (c *recordCapture) records() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	var lens []int
	for b := c.in; len(b) >= 5; {
		n := 5 + int(binary.BigEndian.Uint16(b[3:5]))
		if n > len(b) {
			break
		}
		lens = append(lens, n)
		b = b[n:]
	}
	return lens
}

type dialResult struct {
	conn      *UConn
	records   []int // up to and including the echo
	hello     []uint16
	helloLens []int
}

func dialReality(t *testing.T, server *realityServer, browser string) dialResult {
	t.Helper()
	return dialRealityAs(t, server, browser, "chrome")
}

func dialRealityAs(t *testing.T, server *realityServer, browser, fingerprint string) dialResult {
	t.Helper()
	raw, err := gonet.Dial("tcp", server.addr)
	if err != nil {
		t.Fatal(err)
	}
	capture := &recordCapture{Conn: raw}
	host, portStr, _ := gonet.SplitHostPort(server.addr)
	port, _ := strconv.Atoi(portStr)
	dest := net.TCPDestination(net.ParseAddress(host), net.Port(port))
	config := &Config{
		Fingerprint: fingerprint,
		ServerName:  testServerName,
		PublicKey:   server.public,
		ShortId:     make([]byte, 8),
		SpiderX:     "/",
		SpiderY:     make([]int64, 10),
		Browser:     browser,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := UClient(capture, config, ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	uConn := conn.(*UConn)
	t.Cleanup(func() { uConn.Close() })
	uConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := uConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(uConn, reply); err != nil || string(reply) != "ping" {
		t.Fatalf("echo %q: %v", reply, err)
	}
	types, lens := capture.helloExtensionLens()
	return dialResult{conn: uConn, records: capture.records(), hello: types, helloLens: lens}
}

func testResumption(t *testing.T, target string) {
	server := startRealityServer(t, target)
	key := target + " " + testServerName + " 2"
	shape := reality.LoadTicketShape(key)

	first := dialReality(t, server, "auto")
	if first.conn.ConnectionState().DidResume || !first.conn.Verified {
		t.Fatal("the first connection is a full, verified handshake")
	}
	second := dialReality(t, server, "auto")
	if !second.conn.ConnectionState().DidResume {
		t.Fatal("the second connection resumes")
	}
	if !second.conn.Verified {
		t.Fatal("a resumed connection is verified")
	}
	t.Logf("full %v, resumed %v, target resumes %v", first.records, second.records, shape.ResRecords)

	// ServerHello, ChangeCipherSpec, EncryptedExtensions, Finished, then
	// the tickets: as the target resumes its own.
	if len(second.records) < 4+shape.ResTickets {
		t.Fatalf("resumed records %v", second.records)
	}
	if second.records[0] != first.records[0]+shape.HelloDelta {
		t.Fatalf("resumed ServerHello %d, full %d", second.records[0], first.records[0])
	}
	// EncryptedExtensions changes as the target's does between a full and
	// a resumed handshake: crypto/tls drops 4 bytes.
	ee := first.records[2] + shape.ResRecords[0] - shape.FullRecords[0]
	if second.records[2] != ee || second.records[3] != shape.ResRecords[1] {
		t.Fatalf("resumed EncryptedExtensions and Finished %v, target %v", second.records[2:4], shape.ResRecords)
	}
	for i := 0; i < shape.ResTickets; i++ {
		if second.records[4+i] != shape.ResRecords[2+i] {
			t.Fatalf("resumed ticket record %d is %d, the target's %d", i, second.records[4+i], shape.ResRecords[2+i])
		}
	}

	// Each ticket is used once; the server issues new ones on resumption.
	for range 3 {
		if c := dialReality(t, server, "auto"); !c.conn.ConnectionState().DidResume {
			t.Fatal("later connections resume too")
		}
	}
}

func TestResumptionGoTarget(t *testing.T) {
	testResumption(t, goTarget(t))
}

func TestResumptionOpenSSLTarget(t *testing.T) {
	testResumption(t, opensslTarget(t))
}

// Tickets too short to carry a session, ids of sessions the server keeps:
// REALITY issues and keeps such ids too.
func TestResumptionSessionCacheTarget(t *testing.T) {
	target := opensslTarget(t, "stateful")
	testResumption(t, target)
	shape := reality.LoadTicketShape(target + " " + testServerName + " 2")
	if shape.TicketLen > 64 {
		t.Fatalf("the target's tickets are session ids: %d bytes", shape.TicketLen)
	}
}

func TestNoResumptionWithoutBrowser(t *testing.T) {
	target := opensslTarget(t)
	server := startRealityServer(t, target)
	full := dialReality(t, server, "")
	again := dialReality(t, server, "")
	if again.conn.ConnectionState().DidResume || !again.conn.Verified {
		t.Fatal("without browser every handshake is full")
	}
	// No tickets: the records after the handshake are the empty ones of
	// the target's lengths, as before.
	if len(full.records) != len(again.records) {
		t.Fatalf("records %v and %v", full.records, again.records)
	}
}

func testTicketKey(server *realityServer) string {
	host, portStr, _ := gonet.SplitHostPort(server.addr)
	port, _ := strconv.Atoi(portStr)
	dest := net.TCPDestination(net.ParseAddress(host), net.Port(port))
	return ticketKey(&Config{Fingerprint: "chrome", PublicKey: server.public, ShortId: make([]byte, 8)}, dest, testServerName)
}

func TestResumptionRejectedTicketFallsBackToFullHandshake(t *testing.T) {
	server := startRealityServer(t, opensslTarget(t))
	dialReality(t, server, "auto")
	key := testTicketKey(server)
	var corrupted []*utls.ClientSessionState
	for session := tickets.pop(key); session != nil; session = tickets.pop(key) {
		ticket, state, err := session.ResumptionState()
		if err != nil {
			t.Fatal(err)
		}
		ticket = bytes.Clone(ticket)
		ticket[len(ticket)-1] ^= 1
		cs, err := utls.NewResumptionState(ticket, state)
		if err != nil {
			t.Fatal(err)
		}
		corrupted = append(corrupted, cs)
	}
	if len(corrupted) == 0 {
		t.Fatal("no tickets after a full handshake")
	}
	for _, cs := range corrupted {
		tickets.push(key, cs)
	}
	c := dialReality(t, server, "auto")
	if c.conn.ConnectionState().DidResume || !c.conn.Verified {
		t.Fatal("a ticket the server rejects leads to a full, verified handshake")
	}
	if c := dialReality(t, server, "auto"); !c.conn.ConnectionState().DidResume {
		t.Fatal("the tickets of that full handshake resume")
	}
}

func TestTicketStoreKeepsTwoPerServer(t *testing.T) {
	store := &ticketStore{sessions: make(map[string][]*utls.ClientSessionState)}
	a, b, c := &utls.ClientSessionState{}, &utls.ClientSessionState{}, &utls.ClientSessionState{}
	store.push("k", a)
	store.push("k", b)
	store.push("k", c)
	if store.pop("k") != c || store.pop("k") != b || store.pop("k") != nil {
		t.Fatal("the store keeps the two newest tickets, each popped once")
	}
}

func TestUnverifiedConnectionKeepsNoTickets(t *testing.T) {
	key := "unverified"
	cache := &connTickets{key: key, conn: &UConn{}}
	cache.Put("", &utls.ClientSessionState{})
	if session := tickets.pop(key); session != nil {
		t.Fatal("a ticket from a connection not verified as REALITY is not kept")
	}
	cache.conn.Verified = true
	cache.Put("", &utls.ClientSessionState{})
	if session := tickets.pop(key); session == nil {
		t.Fatal("a verified connection's ticket is kept")
	}
}

func TestNoTicketsWhenTheTargetIssuesNone(t *testing.T) {
	certPEM, keyPEM := testCertificate(t)
	cert, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates:           []gotls.Certificate{cert},
		NextProtos:             []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true,
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
	server := startRealityServer(t, ln.Addr().String())
	for range 2 {
		if c := dialReality(t, server, "auto"); c.conn.ConnectionState().DidResume || !c.conn.Verified {
			t.Fatal("a target without tickets: neither does REALITY issue any")
		}
	}
	if tickets.pop(testTicketKey(server)) != nil {
		t.Fatal("no tickets were issued")
	}
}

// A fingerprint whose ClientHello carries a pre_shared_key of its own
// cannot be built without a ticket; the dial fails instead of panicking.
func TestPSKFingerprintFailsWithoutPanic(t *testing.T) {
	raw, err := gonet.Dial("tcp", goTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{
		Fingerprint: "hellochrome_100_psk",
		ServerName:  testServerName,
		PublicKey:   make([]byte, 32),
		ShortId:     make([]byte, 8),
		SpiderY:     make([]int64, 10),
	}
	if _, err := UClient(raw, config, context.Background(), net.TCPDestination(net.LocalHostIP, 443)); err == nil {
		t.Fatal("the ClientHello cannot be built")
	}
}

// Firefox drops the empty session_ticket extension when it offers a ticket;
// Chrome keeps it. pre_shared_key comes last in both.
func TestResumptionHelloFollowsTheBrowser(t *testing.T) {
	server := startRealityServer(t, goTarget(t))
	for fingerprint, keepsSessionTicket := range map[string]bool{"firefox": false, "chrome": true} {
		full := dialRealityAs(t, server, "auto", fingerprint)
		resumed := dialRealityAs(t, server, "auto", fingerprint)
		if !resumed.conn.ConnectionState().DidResume {
			t.Fatalf("%s: the second connection resumes", fingerprint)
		}
		has := func(types []uint16, want uint16) bool { return slices.Contains(types, want) }
		if !has(full.hello, 35) || has(full.hello, 41) {
			t.Fatalf("%s: full ClientHello %v", fingerprint, full.hello)
		}
		if resumed.hello[len(resumed.hello)-1] != 41 || has(resumed.hello, 35) != keepsSessionTicket {
			t.Fatalf("%s: resumed ClientHello %v", fingerprint, resumed.hello)
		}
		if !keepsSessionTicket && len(resumed.hello) != len(full.hello) {
			t.Fatalf("%s: pre_shared_key takes session_ticket's place: %v, %v", fingerprint, full.hello, resumed.hello)
		}
		ech := func(r dialResult) int {
			return r.helloLens[slices.Index(r.hello, 0xfe0d)]
		}
		// The target's tickets are 105 bytes with a SHA-256 binder: a
		// pre_shared_key of 152 bytes, 160 rounded up.
		if grow := ech(resumed) - ech(full); !keepsSessionTicket && grow != 160 {
			t.Fatalf("%s: GREASE ECH grows by %d with a ticket, Firefox's by 160", fingerprint, grow)
		}
	}
}

func TestNoTicketOfferedForAWhileAfterOneFailed(t *testing.T) {
	defer func(f func(*utls.ClientSessionState) bool) { usableTicket = f }(usableTicket)
	usableTicket = func(*utls.ClientSessionState) bool { return true }
	store := &ticketStore{sessions: make(map[string][]*utls.ClientSessionState)}
	store.push("k", &utls.ClientSessionState{})
	store.fail("k")
	store.push("k", &utls.ClientSessionState{})
	if store.offer("k") != nil {
		t.Fatal("no ticket is offered right after one failed")
	}
	store.failed["k"] = time.Now().Add(-ticketBackoff - time.Second)
	if store.offer("k") == nil {
		t.Fatal("tickets are offered again after the backoff, and those collected meanwhile kept")
	}
}

// Fingerprints whose browser does not resume, such as safari, keep working
// with browser set, with full handshakes.
func TestBrowserWithFingerprintThatDoesNotResume(t *testing.T) {
	server := startRealityServer(t, goTarget(t))
	for range 2 {
		if c := dialRealityAs(t, server, "auto", "safari"); c.conn.ConnectionState().DidResume || !c.conn.Verified {
			t.Fatal("safari: full, verified handshakes")
		}
	}
}

var decryptErrorAlert = []byte{21, 3, 3, 0, 2, 2, 51}

// A censor that saw a ticket on the wire offers it with a binder it cannot
// compute. A server that issued the ticket refuses it with decrypt_error,
// as the target refuses its own; REALITY did a full handshake, through the
// target that does not know the ticket.
func TestTicketWithWrongBinderIsRefused(t *testing.T) {
	server := startRealityServer(t, opensslTarget(t))
	dialReality(t, server, "auto")
	key := testTicketKey(server)

	// The client's own ClientHello, REALITY-authenticated, binder spoiled.
	// OpenSSL targets give two tickets: one for each ClientHello. The
	// failed handshake drops the client's tickets, so both are taken first.
	session, spare := tickets.pop(key), tickets.pop(key)
	if session == nil || spare == nil {
		t.Fatal("no tickets")
	}
	tickets.push(key, session)
	raw, err := gonet.Dial("tcp", server.addr)
	if err != nil {
		t.Fatal(err)
	}
	capture := &recordCapture{Conn: raw, spoilBinder: true}
	host, portStr, _ := gonet.SplitHostPort(server.addr)
	port, _ := strconv.Atoi(portStr)
	config := &Config{
		Fingerprint: "chrome", ServerName: testServerName, PublicKey: server.public,
		ShortId: make([]byte, 8), SpiderY: make([]int64, 10), Browser: "auto",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := UClient(capture, config, ctx, net.TCPDestination(net.ParseAddress(host), net.Port(port))); err == nil {
		t.Fatal("the handshake fails")
	} else {
		t.Logf("client: %v", err)
	}
	if got := capture.received(); !bytes.Equal(got, decryptErrorAlert) {
		t.Fatalf("authenticated, the server answers % x, want decrypt_error", got)
	}

	// The ticket in a ClientHello of the censor's own.
	raw, err = gonet.Dial("tcp", server.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	probe := &recordCapture{Conn: raw, spoilBinder: true}
	// InsecureSkipTimeVerify: REALITY's certificate in the session has no
	// validity, and Go offers no ticket for an expired one.
	uConn := utls.UClient(probe, &utls.Config{
		ServerName: testServerName, InsecureSkipVerify: true, InsecureSkipTimeVerify: true,
		NextProtos: []string{"h2", "http/1.1"}, ClientSessionCache: &connTickets{key: key, conn: &UConn{}, session: spare},
	},
		utls.HelloGolang)
	uConn.SetDeadline(time.Now().Add(5 * time.Second))
	uConn.Handshake()
	if got := probe.received(); !bytes.Equal(got, decryptErrorAlert) {
		t.Fatalf("not authenticated, the server answers % x, want decrypt_error", got[:min(len(got), 16)])
	}
}

// Chromium verifies a server's certificate once in 30 minutes; meanwhile
// full handshakes take no time for it.
func TestVerifyDelayOncePerServer(t *testing.T) {
	delay := verifyDelay(utls.HelloChrome_Auto, "verify-once")
	if d := delay(); d < 15*time.Millisecond {
		t.Fatalf("the first verification takes %v", d)
	}
	if d := delay(); d > time.Millisecond {
		t.Fatalf("a cached one takes %v", d)
	}
	verifications.at["verify-once"] = time.Now().Add(-verifyCacheTTL - time.Second)
	if d := delay(); d < 15*time.Millisecond {
		t.Fatalf("after 30 minutes the certificate is verified again: %v", d)
	}
	if verifyDelay(utls.HelloSafari_Auto, "x") != nil {
		t.Fatal("no delay for fingerprints not measured")
	}
}

// An outbound that requires ML-DSA-65 does not resume with a ticket another
// outbound to the same server got without it: the server has no ML-DSA
// key, and only a full handshake would have shown that.
func TestResumptionKeepsTheMldsa65Policy(t *testing.T) {
	server := startRealityServer(t, goTarget(t))
	dialReality(t, server, "auto") // a ticket, without ML-DSA
	raw, err := gonet.Dial("tcp", server.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	host, portStr, _ := gonet.SplitHostPort(server.addr)
	port, _ := strconv.Atoi(portStr)
	strict := &Config{
		Fingerprint:   "chrome",
		ServerName:    testServerName,
		PublicKey:     server.public,
		ShortId:       make([]byte, 8),
		SpiderY:       make([]int64, 10),
		Browser:       "auto",
		Mldsa65Verify: make([]byte, 1952),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := UClient(raw, strict, ctx, net.TCPDestination(net.ParseAddress(host), net.Port(port)))
	if err == nil {
		resumed := conn.(*UConn).ConnectionState().DidResume
		conn.Close()
		t.Fatalf("the ML-DSA-65 outbound connected (resumed %v) to a server without the key", resumed)
	}
}

// expire returns session with its use-by time, the last 12 bytes but the
// age add of a TLS 1.3 client session's encoding, in the past.
func expire(t *testing.T, session *utls.ClientSessionState) *utls.ClientSessionState {
	t.Helper()
	ticket, state, err := session.ResumptionState()
	if err != nil {
		t.Fatal(err)
	}
	b, err := state.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(b[len(b)-12:], uint64(time.Now().Add(-time.Minute).Unix()))
	parsed, err := utls.ParseSessionState(b)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := utls.NewResumptionState(ticket, parsed)
	if err != nil {
		t.Fatal(err)
	}
	return expired
}

// An expired ticket is not offered, and Firefox's full ClientHello goes out
// as it is, session_ticket and GREASE ECH included: not the ClientHello of
// a resumption without its pre_shared_key.
func TestExpiredTicketLeavesTheFullClientHello(t *testing.T) {
	server := startRealityServer(t, goTarget(t))
	full := dialRealityAs(t, server, "auto", "firefox")
	host, portStr, _ := gonet.SplitHostPort(server.addr)
	port, _ := strconv.Atoi(portStr)
	key := ticketKey(&Config{Fingerprint: "firefox", PublicKey: server.public, ShortId: make([]byte, 8)},
		net.TCPDestination(net.ParseAddress(host), net.Port(port)), testServerName)
	var expired []*utls.ClientSessionState
	for session := tickets.pop(key); session != nil; session = tickets.pop(key) {
		expired = append(expired, expire(t, session))
	}
	if len(expired) == 0 {
		t.Fatal("no tickets")
	}
	for _, session := range expired {
		tickets.push(key, session)
	}
	again := dialRealityAs(t, server, "auto", "firefox")
	if again.conn.ConnectionState().DidResume || slices.Contains(again.hello, 41) {
		t.Fatal("an expired ticket is not offered")
	}
	if !slices.Equal(again.hello, full.hello) || !slices.Equal(again.helloLens, full.helloLens) {
		t.Fatalf("the full ClientHello %v %v, want Firefox's %v %v", again.hello, again.helloLens, full.hello, full.helloLens)
	}
}
