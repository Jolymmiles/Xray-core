package reality_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"fmt"
	stdnet "net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tcp"
)

const (
	spiderChildEnv   = "XRAY_REALITY_SPIDER_TEST"
	spiderServerName = "cover.test"
)

// inTrustingChild runs the calling test again in a child process in which a
// test certificate authority is trusted like a public one, as the spider
// needs a real certificate. It reports whether it runs in that child.
func inTrustingChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(spiderChildEnv) == t.Name() {
		authority, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature))
		parsed, err := x509.ParseCertificate(authority.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(parsed)
		x509.SetFallbackRoots(roots)
		testAuthority = authority
		return true
	}
	child := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.timeout=120s", "-test.v")
	child.Env = append(os.Environ(), spiderChildEnv+"="+t.Name(), "GODEBUG=x509usefallbackroots=1")
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("child test failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "--- PASS: "+t.Name()+" ") {
		t.Fatalf("child did not run %s:\n%s", t.Name(), output)
	}
	return false
}

// testAuthority signs the cover's certificate; set in the child only.
var testAuthority *cert.Certificate

// spiderCover is the real site behind the REALITY server: an HTTPS server
// with HTTP/2 whose certificate the client trusts.
type spiderCover struct {
	address string
	mu      sync.Mutex
	// spiderConn is the cover's connection that carried the spider's first
	// request; closed is closed when that connection closes.
	spiderConn string
	closed     chan struct{}
}

func startSpiderCover(t *testing.T, handler func(cover *spiderCover, w http.ResponseWriter, r *http.Request)) *spiderCover {
	t.Helper()
	leaf, _ := cert.MustGenerate(testAuthority, cert.CommonName(spiderServerName), cert.DNSNames(spiderServerName))
	certificate, err := gotls.X509KeyPair(leaf.ToPEM())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cover := &spiderCover{address: listener.Addr().String(), closed: make(chan struct{})}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cover.mu.Lock()
			if cover.spiderConn == "" {
				cover.spiderConn = r.RemoteAddr
			}
			cover.mu.Unlock()
			handler(cover, w, r)
		}),
		TLSConfig:   &gotls.Config{Certificates: []gotls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}},
		IdleTimeout: 10 * time.Minute,
		ConnState: func(conn stdnet.Conn, state http.ConnState) {
			if state != http.StateClosed {
				return
			}
			cover.mu.Lock()
			defer cover.mu.Unlock()
			if conn.RemoteAddr().String() == cover.spiderConn {
				close(cover.closed)
				cover.spiderConn = "closed"
			}
		},
	}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return cover
}

// startREALITYServer runs a REALITY server that forwards to cover every
// client it does not authenticate.
func startREALITYServer(t *testing.T, cover string) string {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := (&reality.Config{
		Dest:        cover,
		Type:        "tcp",
		ServerNames: []string{spiderServerName},
		PrivateKey:  privateKey.Bytes(),
		ShortIds:    [][]byte{{1, 2, 3, 4, 5, 6, 7, 8}},
	}).GetREALITYConfig()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				if realityConn, err := reality.Server(conn, serverConfig); err == nil {
					_ = realityConn.Close()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// dialSpider dials the REALITY server over TCP with a public key that is not
// the server's, so the server forwards the client to the cover and the
// client gets the cover's real certificate.
func dialSpider(t *testing.T, server, spiderX string, spiderY []int64) {
	t.Helper()
	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	address, err := stdnet.ResolveTCPAddr("tcp", server)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := tcp.Dial(ctx, net.TCPDestination(net.LocalHostIP, net.Port(address.Port)), &internet.MemoryStreamConfig{
		ProtocolName:     "tcp",
		ProtocolSettings: &tcp.Config{},
		SecuritySettings: &reality.Config{
			Fingerprint: "chrome",
			ServerName:  spiderServerName,
			PublicKey:   wrongKey.PublicKey().Bytes(),
			ShortId:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
			SpiderX:     spiderX,
			SpiderY:     spiderY,
		},
	})
	if err == nil {
		conn.Close()
		t.Fatal("a client the server did not authenticate got a connection")
	}
	if !strings.Contains(err.Error(), "processed invalid connection") {
		t.Fatalf("dial failed with %v, want the spider's error", err)
	}
}

// Over TCP, as over the other transports, the spider keeps browsing after
// Dial has returned: the connection is the spider's, not closed under it.
func TestREALITYSpiderOverTCP(t *testing.T) {
	if !inTrustingChild(t) {
		return
	}
	release := make(chan struct{})
	requests := make(chan string, 16)
	cover := startSpiderCover(t, func(_ *spiderCover, w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		if r.URL.Path == "/first" {
			// Answer only once Dial has returned.
			<-release
		}
		fmt.Fprint(w, `<html><a href="/second">next</a></html>`)
	})
	server := startREALITYServer(t, cover.address)
	// One worker making one request after the first page.
	dialSpider(t, server, "/first", []int64{0, 0, 1, 1, 1, 1, 0, 0, 0, 0})
	select {
	case path := <-requests:
		if path != "/first" {
			t.Fatalf("first request for %s", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the spider sent no request")
	}
	close(release)
	select {
	case <-requests:
	case <-time.After(5 * time.Second):
		t.Fatal("the spider sent no request after Dial returned: its connection was closed")
	}
}

// awaitClosed waits until the cover's connection that carried the spider is
// closed, and reports how long that took.
func awaitClosed(t *testing.T, cover *spiderCover, limit time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	select {
	case <-cover.closed:
		return time.Since(start)
	case <-time.After(limit):
		t.Fatalf("the spider's connection is still open after %v", limit)
		return 0
	}
}

// The spider owns the connection it is handed for a lease: when it ends the
// connection is closed, whether the spider is done or still waiting.
func TestREALITYSpiderLease(t *testing.T) {
	if !inTrustingChild(t) {
		return
	}
	const lease = 500 * time.Millisecond
	reality.SetSpiderLease(t, lease)
	for name, handler := range map[string]func(*spiderCover, http.ResponseWriter, *http.Request){
		"idle after the page": func(_ *spiderCover, w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "<html></html>")
		},
		"response never comes": func(_ *spiderCover, _ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		},
	} {
		t.Run(name, func(t *testing.T) {
			cover := startSpiderCover(t, handler)
			server := startREALITYServer(t, cover.address)
			dialSpider(t, server, "/", make([]int64, 10))
			awaitClosed(t, cover, lease+5*time.Second)
		})
	}
}

// A redirect to another host does not open a second HTTP/2 session on the
// spider's one connection, which the cover would reject at once.
func TestREALITYSpiderKeepsOneConnection(t *testing.T) {
	if !inTrustingChild(t) {
		return
	}
	// Well past the second the cover's HTTP/2 server waits after a protocol
	// error before it closes the connection.
	const lease = 4 * time.Second
	reality.SetSpiderLease(t, lease)
	redirected := make(chan struct{})
	cover := startSpiderCover(t, func(_ *spiderCover, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.test/", http.StatusFound)
		close(redirected)
	})
	server := startREALITYServer(t, cover.address)
	dialSpider(t, server, "/", make([]int64, 10))
	select {
	case <-redirected:
	case <-time.After(5 * time.Second):
		t.Fatal("the spider sent no request")
	}
	if open := awaitClosed(t, cover, lease+5*time.Second); open < lease/2 {
		t.Fatalf("the connection closed %v after the redirect, before the lease ended", open)
	}
}
