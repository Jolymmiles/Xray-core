package xdns

import (
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/tls/refreshtest"
)

func h3ResolverConfig(congestion string) *ResolverProto {
	return &ResolverProto{
		Type:       "https",
		Addr:       "https://192.0.2.53/dns-query",
		Worker:     1,
		TlsConfig:  &tls.Config{ServerName: "dns.example", NextProtocol: []string{"h3"}},
		QuicConfig: &internet.QuicParams{Congestion: congestion, BrutalUp: 1 << 20},
	}
}

// A QUIC dial that never completes is canceled by Close; the socket it dialed
// has to be closed with it rather than left to the garbage collector.
func TestDOHResolverH3ClosesTheSocketOfAFailedDial(t *testing.T) {
	dialed := make(chan *trackedPacketConn, 1)
	dialer := &finalmask.Dialer{
		DialUDP: func(net.Destination) (net.Conn, error) {
			socket := &trackedPacketConn{blockingPacketConn: newBlockingPacketConn()}
			dialed <- socket
			return &net.PacketConnWrapper{
				PacketConn: socket,
				Dest:       &net.UDPAddr{IP: net.IP{192, 0, 2, 53}, Port: 443},
			}, nil
		},
	}
	resolver, err := NewDOHResolver(h3ResolverConfig(""), dialer)
	if err != nil {
		t.Fatal(err)
	}

	resolver.Send([]byte("query"))
	var socket *trackedPacketConn
	select {
	case socket = <-dialed:
	case <-time.After(5 * time.Second):
		resolver.Close()
		t.Fatal("the h3 resolver never dialed")
	}
	resolver.Close()

	select {
	case <-socket.closed:
	case <-time.After(5 * time.Second):
		socket.Close()
		t.Fatal("the socket of a dial that Close canceled was left open")
	}
}

// "brutal" is valid QUIC congestion for Hysteria, where the server agrees to
// it. A DoH server does not, and the h3 dial panicked on it in a goroutine
// nothing recovers, taking the process down on the first query.
func TestNewDOHResolverRejectsBrutalCongestion(t *testing.T) {
	dialer := &finalmask.Dialer{DialUDP: func(net.Destination) (net.Conn, error) {
		t.Error("a resolver with an unsupported congestion control dialed")
		return nil, io.ErrClosedPipe
	}}
	if resolver, err := NewDOHResolver(h3ResolverConfig("brutal"), dialer); err == nil {
		resolver.Close()
		t.Fatal(`NewDOHResolver accepted "congestion": "brutal"`)
	}
	for _, congestion := range []string{"", "reno", "bbr", "force-brutal"} {
		resolver, err := NewDOHResolver(h3ResolverConfig(congestion), dialer)
		if err != nil {
			t.Fatalf("NewDOHResolver refused %q: %v", congestion, err)
		}
		resolver.Close()
	}
}

// Over h1 and h2 the resolver dials TLS itself, so it names the server of its
// URL as h3 does; without a "serverName" only a pinned leaf certificate or
// verifyPeerCertByName could verify the server.
func TestDOHResolverTLSNamesTheServerOfItsURL(t *testing.T) {
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign))
	issued, _ := cert.MustGenerate(ca, cert.DNSNames("dns.example"))
	leafPEM, leafKey := issued.ToPEM()
	leaf, err := gotls.X509KeyPair(leafPEM, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	names := make(chan string, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("answer"))
	}))
	server.TLS = &gotls.Config{
		Certificates: []gotls.Certificate{leaf},
		GetConfigForClient: func(hello *gotls.ClientHelloInfo) (*gotls.Config, error) {
			names <- hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	caPEM, _ := ca.ToPEM()
	dialer := &finalmask.Dialer{DialTCP: func(net.Destination) (net.Conn, error) {
		return stdnet.Dial("tcp", server.Listener.Addr().String())
	}}
	resolver, err := NewDOHResolver(&ResolverProto{
		Type:   "https",
		Addr:   "https://dns.example/dns-query",
		Worker: 1,
		TlsConfig: &tls.Config{Certificate: []*tls.Certificate{{
			Certificate: caPEM,
			Usage:       tls.Certificate_AUTHORITY_VERIFY,
		}}},
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)

	resolver.Send([]byte("query"))
	answer := make(chan string, 1)
	go func() {
		p := make([]byte, 64)
		n, _ := resolver.Read(p)
		answer <- string(p[:n])
	}()
	select {
	case got := <-answer:
		if got != "answer" {
			t.Fatalf("read %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer through a resolver without a serverName")
	}
	if name := <-names; name != "dns.example" {
		t.Fatalf("the ClientHello named %q", name)
	}
}

// Over h3, http3 names the server in the handshake of a copy of the TLS config,
// while the check of a pinned certificate reads the name from the config it
// was built in; that one has to name the server of the URL as well.
func TestDOHResolverH3PinnedCAWithoutServerName(t *testing.T) {
	ca, caHash := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign))
	issued, _ := cert.MustGenerate(ca, cert.DNSNames("dns.example"))
	certPEM, keyPEM := issued.ToPEM()
	caPEM, _ := ca.ToPEM()
	leaf, err := gotls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: &gotls.Config{Certificates: []gotls.Certificate{leaf}},
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("answer")) }),
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(socket) }()
	t.Cleanup(func() {
		server.Close()
		socket.Close()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("the h3 server did not stop")
		}
	})

	dialer := &finalmask.Dialer{DialUDP: func(net.Destination) (net.Conn, error) {
		local, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return &net.PacketConnWrapper{PacketConn: local, Dest: socket.LocalAddr()}, nil
	}}
	resolver, err := NewDOHResolver(&ResolverProto{
		Type:       "https",
		Addr:       "https://dns.example/dns-query",
		Worker:     1,
		TlsConfig:  &tls.Config{NextProtocol: []string{"h3"}, PinnedPeerCertSha256: [][]byte{caHash[:]}},
		QuicConfig: &internet.QuicParams{DisableChromeParrot: true},
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "POST", "https://dns.example/dns-query", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := resolver.(*DOHResolver).client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if answer, err := io.ReadAll(response.Body); err != nil || string(answer) != "answer" {
		t.Fatalf("answer %q, error %v", answer, err)
	}
}

// A resolver refused for its congestion control builds no TLS config, and one
// that dials again reuses the TLS config it was built with. That is a client's
// config, so a certificate in it starts no refresh worker that would outlive
// the resolver.
func TestDOHResolverBuildsItsTLSConfigOnce(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		tlsConfig, baseline := refreshtest.Config(t, tls.Certificate_ENCIPHERMENT)
		tlsConfig.NextProtocol = []string{"h3"}
		for range 3 {
			resolver, err := NewDOHResolver(&ResolverProto{
				Type: "https", Addr: "https://dns.example/dns-query", Worker: 1,
				TlsConfig: tlsConfig, QuicConfig: &internet.QuicParams{Congestion: "brutal"},
			}, &finalmask.Dialer{})
			if err == nil {
				resolver.Close()
				t.Fatal(`NewDOHResolver accepted "congestion": "brutal"`)
			}
		}
		if workers := refreshtest.Workers() - baseline; workers != 0 {
			t.Fatalf("three refused resolvers left %d certificate refresh workers", workers)
		}
	})
	t.Run("redialed", func(t *testing.T) {
		tlsConfig, baseline := refreshtest.Config(t, tls.Certificate_ENCIPHERMENT)
		dialer := &finalmask.Dialer{DialTCP: func(net.Destination) (net.Conn, error) {
			local, peer := stdnet.Pipe()
			peer.Close()
			return tcpAddressed{local}, nil
		}}
		resolver, err := NewDOHResolver(&ResolverProto{
			Type: "https", Addr: "https://dns.example/dns-query", Worker: 1, TlsConfig: tlsConfig,
		}, dialer)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(resolver.Close)
		transport := resolver.(*DOHResolver).client.Transport.(*http.Transport)
		for range 3 {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := transport.DialTLSContext(ctx, "tcp", "dns.example:443")
			cancel()
			if err == nil {
				conn.Close()
				t.Fatal("a TLS handshake with a closed peer succeeded")
			}
		}
		if workers := refreshtest.Workers() - baseline; workers != 0 {
			t.Fatalf("a resolver that dialed three times started %d certificate refresh workers", workers)
		}
	})
	t.Run("closed", func(t *testing.T) {
		tlsConfig, baseline := refreshtest.Config(t, tls.Certificate_ENCIPHERMENT)
		resolver, err := NewDOHResolver(&ResolverProto{
			Type: "https", Addr: "https://dns.example/dns-query", Worker: 1, TlsConfig: tlsConfig,
		}, &finalmask.Dialer{})
		if err != nil {
			t.Fatal(err)
		}
		resolver.Close()
		if workers := refreshtest.Workers() - baseline; workers != 0 {
			t.Fatalf("a closed resolver left %d certificate refresh workers", workers)
		}
	})
}

// tcpAddressed is a pipe that the resolver takes for a TCP connection.
type tcpAddressed struct{ stdnet.Conn }

func (c tcpAddressed) RemoteAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IP{127, 0, 0, 1}, Port: 443}
}

// redirectingDOHHandler answers the URL's path with a redirect of the given
// code to another path of the same server, and counts the requests that
// reached the path it redirects to.
func redirectingDOHHandler(code int, followed chan<- string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/moved", code)
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		followed <- r.Method
		w.Write([]byte("<html>not a DNS message</html>"))
	})
	return mux
}

// A DoH server is named by the configuration alone: a redirect, from the
// server or from whoever can answer for it, is a failed query. Followed, a
// 301, 302 or 303 turns the query into a GET without a body, and the page it
// fetches was read as the answer.
func TestDOHResolverRefusesRedirects(t *testing.T) {
	ca, caHash := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign))
	issued, _ := cert.MustGenerate(ca, cert.DNSNames("dns.example"))
	certPEM, keyPEM := issued.ToPEM()
	caPEM, _ := ca.ToPEM()
	leaf, err := gotls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	codes := []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect}

	t.Run("tcp", func(t *testing.T) {
		for _, code := range codes {
			followed := make(chan string, 10)
			server := httptest.NewUnstartedServer(redirectingDOHHandler(code, followed))
			server.EnableHTTP2 = true
			server.TLS = &gotls.Config{Certificates: []gotls.Certificate{leaf}}
			server.StartTLS()
			t.Cleanup(server.Close)
			dialer := &finalmask.Dialer{DialTCP: func(net.Destination) (net.Conn, error) {
				return stdnet.Dial("tcp", server.Listener.Addr().String())
			}}
			resolver, err := NewDOHResolver(&ResolverProto{
				Type: "https", Addr: "https://dns.example/dns-query", Worker: 1,
				TlsConfig: &tls.Config{PinnedPeerCertSha256: [][]byte{caHash[:]}},
			}, dialer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(resolver.Close)
			assertRedirectRefused(t, resolver.(*DOHResolver), code, followed)
		}
	})
	t.Run("h3", func(t *testing.T) {
		for _, code := range codes {
			followed := make(chan string, 10)
			socket, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &http3.Server{
				TLSConfig: &gotls.Config{Certificates: []gotls.Certificate{leaf}},
				Handler:   redirectingDOHHandler(code, followed),
			}
			served := make(chan error, 1)
			go func() { served <- server.Serve(socket) }()
			t.Cleanup(func() {
				server.Close()
				socket.Close()
				select {
				case <-served:
				case <-time.After(5 * time.Second):
					t.Error("the h3 server did not stop")
				}
			})
			dialer := &finalmask.Dialer{DialUDP: func(net.Destination) (net.Conn, error) {
				local, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				return &net.PacketConnWrapper{PacketConn: local, Dest: socket.LocalAddr()}, nil
			}}
			resolver, err := NewDOHResolver(&ResolverProto{
				Type: "https", Addr: "https://dns.example/dns-query", Worker: 1,
				TlsConfig:  &tls.Config{NextProtocol: []string{"h3"}, PinnedPeerCertSha256: [][]byte{caHash[:]}},
				QuicConfig: &internet.QuicParams{DisableChromeParrot: true},
			}, dialer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(resolver.Close)
			assertRedirectRefused(t, resolver.(*DOHResolver), code, followed)
		}
	})
}

// assertRedirectRefused sends one query, which has to fail on the redirect
// without a request to where it points.
func assertRedirectRefused(t *testing.T, resolver *DOHResolver, code int, followed <-chan string) {
	t.Helper()
	read := make(chan string, 1)
	go func() {
		p := make([]byte, 64)
		if n, err := resolver.Read(p); err == nil {
			read <- string(p[:n])
		}
	}()
	done := make(chan error, 1)
	go func() { done <- resolver.do([]byte("query")) }()
	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "code "+strconv.Itoa(code)) {
			t.Errorf("a query answered with %d failed with %v", code, err)
		}
		if err == nil {
			// do returns nil only once Read has taken the body.
			t.Errorf("a query answered with %d succeeded with the answer %q", code, <-read)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("a query answered with %d did not return", code)
	}
	select {
	case method := <-followed:
		t.Errorf("a redirect with %d was followed with %s", code, method)
	default:
	}
}
