package splithttp

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

// listenGovernedXH starts an XHTTP listener over TLS through ListenXH, as
// production does, with the flow governor switched as asked.
func listenGovernedXH(t *testing.T, governed, proxyProtocol bool, addConn func(stat.Connection)) string {
	t.Helper()
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "shs"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:  []*tls.Certificate{tls.ParseCertificate(ct)},
			NextProtocol: []string{"h2", "http/1.1"},
		},
	}
	if proxyProtocol {
		settings.SocketSettings = &internet.SocketConfig{AcceptProxyProtocol: true}
	}
	saved := flowEnabled
	flowEnabled = governed
	defer func() { flowEnabled = saved }()
	port := tcp.PickPort()
	ln, err := ListenXH(context.Background(), xnet.LocalHostIP, port, settings, addConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// TestFlowListenerKeepsPeerProvenance sends a PROXY header, TLS and an XHTTP
// stream-one request behind a connection that never sends its PROXY header.
// The server must accept it without waiting for the idle one, and the XHTTP
// connection must carry the real TCP peer and the PROXY source separately,
// exactly as without the governor.
func TestFlowListenerKeepsPeerProvenance(t *testing.T) {
	for _, governed := range []bool{false, true} {
		t.Run(fmt.Sprintf("governed=%v", governed), func(t *testing.T) {
			conns := make(chan stat.Connection, 4)
			addr := listenGovernedXH(t, governed, true, func(c stat.Connection) { conns <- c })

			idle, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer idle.Close()

			deadline := time.Now().Add(3 * time.Second)
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(deadline)
			if _, err := io.WriteString(raw, "PROXY TCP4 192.0.2.1 192.0.2.2 1111 2222\r\n"); err != nil {
				t.Fatal(err)
			}
			tc := gotls.Client(raw, &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"h2"}})
			if err := tc.Handshake(); err != nil {
				t.Fatalf("TLS handshake behind a connection without its PROXY header: %v", err)
			}
			cc, err := (&http2.Transport{}).NewClientConn(tc)
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "POST", "https://localhost/shs/?x_padding="+strings.Repeat("X", 200), strings.NewReader("hello"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatalf("XHTTP request behind a connection without its PROXY header: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("XHTTP stream-one answered %s", resp.Status)
			}

			select {
			case c := <-conns:
				defer c.Close()
				peer, ok := xnet.PhysicalPeer(c)
				if !ok || peer.String() != raw.LocalAddr().String() {
					t.Fatalf("physical peer %v (%v), want the TCP peer %v", peer, ok, raw.LocalAddr())
				}
				source, ok := xnet.AcceptedProxyPeer(c)
				if !ok || source != netip.MustParseAddr("192.0.2.1") {
					t.Fatalf("accepted PROXY source %v (%v), want 192.0.2.1", source, ok)
				}
			case <-ctx.Done():
				t.Fatal("no XHTTP connection reached the inbound")
			}
		})
	}
}

var dateHeader = regexp.MustCompile(`(?m)^Date: [^\r\n]*\r\n`)

// probe opens a fresh connection to addr, speaks TLS with the given ALPN
// unless alpn is empty, sends payload, and returns every byte the server
// answers before it closes or the deadline passes.
func probe(t *testing.T, addr, alpn string, payload []byte) []byte {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	var c net.Conn = raw
	if alpn != "" {
		tc := gotls.Client(raw, &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{alpn}})
		if err := tc.Handshake(); err != nil {
			t.Fatalf("TLS handshake: %v", err)
		}
		if tc.ConnectionState().NegotiatedProtocol != alpn {
			t.Fatalf("negotiated %q, want %q", tc.ConnectionState().NegotiatedProtocol, alpn)
		}
		c = tc
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(c)
	return dateHeader.ReplaceAll(got, nil)
}

// TestFlowListenerAnswersProbesLikeStock compares, byte for byte, what an
// XHTTP TLS listener answers to unauthenticated probes that never reach
// HTTP/2 with the governor on and off: the governor must not change how
// net/http handles TLS, ALPN and HTTP/1.1.
func TestFlowListenerAnswersProbesLikeStock(t *testing.T) {
	stockAddr := listenGovernedXH(t, false, false, func(c stat.Connection) { c.Close() })
	governedAddr := listenGovernedXH(t, true, false, func(c stat.Connection) { c.Close() })
	settings := frames(func(fr *http2.Framer) { fr.WriteSettings() })
	for _, tc := range []struct {
		name    string
		alpn    string
		payload []byte
	}{
		{"plaintext HTTP to the TLS port", "", []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")},
		{"HTTP/1.1 over TLS", "http/1.1", []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")},
		{"HTTP/2 preface after http/1.1 ALPN", "http/1.1", append([]byte(h2Preface), settings...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stock := probe(t, stockAddr, tc.alpn, tc.payload)
			governed := probe(t, governedAddr, tc.alpn, tc.payload)
			if len(stock) == 0 {
				t.Fatal("stock listener answered nothing; the probe does not exercise net/http")
			}
			if !bytes.Equal(governed, stock) {
				t.Fatalf("governed listener answered\n%q\nstock answered\n%q", governed, stock)
			}
		})
	}
	if got := probe(t, stockAddr, "", []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); !bytes.HasPrefix(got, []byte("HTTP/1.0 400 Bad Request\r\n")) {
		t.Fatalf("stock answer to plaintext HTTP changed: %q", got)
	}
}

// serverSettings performs a TLS handshake with ALPN h2 and returns the first
// SETTINGS frame the server sends. It sends the client preface only after
// that frame: net/http's HTTP/2 server writes its SETTINGS before it reads
// the preface, and a governor that waited for the preface would miss them.
func serverSettings(t *testing.T, addr string) map[http2.SettingID]uint32 {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	tc := gotls.Client(raw, &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer tc.Write(append([]byte(h2Preface), frames(func(fr *http2.Framer) { fr.WriteSettings() })...))
	fr := http2.NewFramer(nil, tc)
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("no SETTINGS from the server: %v", err)
		}
		if sf, ok := frame.(*http2.SettingsFrame); ok && !sf.IsAck() {
			values := map[http2.SettingID]uint32{}
			sf.ForeachSetting(func(s http2.Setting) error {
				values[s.ID] = s.Val
				return nil
			})
			return values
		}
	}
}

// TestFlowListenerGovernsTLSHTTP2 checks that the governor still sits on the
// HTTP/2 connections a TLS listener hands to net/http after ALPN, and that
// switching it off leaves the stock SETTINGS.
func TestFlowListenerGovernsTLSHTTP2(t *testing.T) {
	stock := serverSettings(t, listenGovernedXH(t, false, false, func(c stat.Connection) { c.Close() }))
	governed := serverSettings(t, listenGovernedXH(t, true, false, func(c stat.Connection) { c.Close() }))
	// Since the server shows Go's initial window, only the frame size tells.
	if stock[http2.SettingMaxFrameSize] == h2MinMaxFrameSize {
		t.Fatalf("stock server already advertises the governor's values: %v", stock)
	}
	if governed[http2.SettingMaxFrameSize] != h2MinMaxFrameSize || governed[http2.SettingInitialWindowSize] != flowShownUp {
		t.Fatalf("governed server advertises %v, want the governor's frame size and initial window", governed)
	}
}

// TestFlowConnKeepsOptionalInterfaces checks the wrapper against the inner
// connection: net/http sees TLS exactly when the inner connection is TLS,
// and unwrapping and half-close still reach the inner connection.
// Adapted to bdbac60e: newFlowConn is the only constructor; the TLS
// interfaces are the ones net/http itself asserts (*tls.Conn, or
// ConnectionState/HandshakeContext on the fixes branch).
func TestFlowConnKeepsOptionalInterfaces(t *testing.T) {
	plain, peer := net.Pipe()
	defer plain.Close()
	defer peer.Close()
	tlsConn := gotls.Server(plain, &gotls.Config{})
	type tlsStater interface{ ConnectionState() gotls.ConnectionState }
	type tlsHandshaker interface {
		HandshakeContext(context.Context) error
	}
	for _, tc := range []struct {
		name  string
		inner net.Conn
	}{{"plain", plain}, {"tls", tlsConn}} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := newFlowConn(tc.inner, flowDefault, flowDefault).wrap()
			_, innerTLS := tc.inner.(tlsStater)
			if _, ok := wrapped.(tlsStater); ok != innerTLS {
				t.Errorf("wrapper reports TLS %v, inner connection %v", ok, innerTLS)
			}
			_, innerHandshake := tc.inner.(tlsHandshaker)
			if _, ok := wrapped.(tlsHandshaker); ok != innerHandshake {
				t.Errorf("wrapper offers a handshake %v, inner connection %v", ok, innerHandshake)
			}
			unwrap, ok := wrapped.(interface{ NetConn() net.Conn })
			if !ok || unwrap.NetConn() != tc.inner {
				t.Error("wrapper does not unwrap to the inner connection")
			}
			if _, ok := wrapped.(interface{ CloseWrite() error }); !ok {
				t.Error("wrapper hides CloseWrite from net/http")
			}
		})
	}
}

// TestFlowTLSModeFollowsALPN checks that on a TLS connection the governor
// takes HTTP/2 exactly when ALPN picked h2, as net/http does: with any other
// protocol net/http serves HTTP/1.x only, even after an HTTP/2 preface, and
// the governor must not parse that as frames.
// Adapted to bdbac60e: there is no handshake hook, so the client sends the
// HTTP/2 preface after the handshake and the mode is read after the
// governor has seen it, as net/http would read it.
func TestFlowTLSModeFollowsALPN(t *testing.T) {
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	certificate, err := gotls.X509KeyPair(ct.ToPEM())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		alpn string
		want int32
	}{{"h2", flowH2}, {"http/1.1", flowPlain}, {"", flowPlain}} {
		t.Run(fmt.Sprintf("alpn=%q", tc.alpn), func(t *testing.T) {
			serverSide, clientSide := net.Pipe()
			defer serverSide.Close()
			defer clientSide.Close()
			server := gotls.Server(serverSide, &gotls.Config{Certificates: []gotls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}})
			var protos []string
			if tc.alpn != "" {
				protos = []string{tc.alpn}
			}
			client := gotls.Client(clientSide, &gotls.Config{InsecureSkipVerify: true, NextProtos: protos})
			go func() {
				if client.Handshake() == nil {
					client.Write([]byte(h2Preface))
				}
			}()
			wrapped := newFlowConn(server, flowDefault, flowDefault)
			wrapped.wrap()
			buf := make([]byte, len(h2Preface))
			if _, err := io.ReadFull(wrapped, buf); err != nil {
				t.Fatal(err)
			}
			if got := server.ConnectionState().NegotiatedProtocol; got != tc.alpn {
				t.Fatalf("negotiated %q, want %q", got, tc.alpn)
			}
			if got := wrapped.mode.Load(); got != tc.want {
				t.Fatalf("mode %d after ALPN %q, want %d", got, tc.alpn, tc.want)
			}
		})
	}
}

// TestFlowListenerSendsSettingsBeforePreface (added for bdbac60e) states
// the order serverSettings relies on as its own check: after TLS with ALPN
// h2, a stock XHTTP listener sends its SETTINGS before the client preface;
// the governed one must too, since a prober can tell the two apart.
func TestFlowListenerSendsSettingsBeforePreface(t *testing.T) {
	for _, governed := range []bool{false, true} {
		t.Run(fmt.Sprintf("governed=%v", governed), func(t *testing.T) {
			addr := listenGovernedXH(t, governed, false, func(c stat.Connection) { c.Close() })
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(2 * time.Second))
			tc := gotls.Client(raw, &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"h2"}})
			if err := tc.Handshake(); err != nil {
				t.Fatal(err)
			}
			frame, err := http2.NewFramer(nil, tc).ReadFrame()
			if err != nil {
				t.Fatalf("no frame from the server before the client preface: %v", err)
			}
			if _, ok := frame.(*http2.SettingsFrame); !ok {
				t.Fatalf("first frame %v, want SETTINGS", frame)
			}
		})
	}
}

// TestFlowListenerGovernsTLSHTTP2AfterPreface (added for bdbac60e) is
// TestFlowListenerGovernsTLSHTTP2 with the client preface sent first, to
// separate whether the governor rewrites the SETTINGS from when they leave.
func TestFlowListenerGovernsTLSHTTP2AfterPreface(t *testing.T) {
	read := func(addr string) map[http2.SettingID]uint32 {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(2 * time.Second))
		tc := gotls.Client(raw, &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"h2"}})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		tc.Write(append([]byte(h2Preface), frames(func(fr *http2.Framer) { fr.WriteSettings() })...))
		fr := http2.NewFramer(nil, tc)
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				t.Fatalf("no SETTINGS from the server: %v", err)
			}
			if sf, ok := frame.(*http2.SettingsFrame); ok && !sf.IsAck() {
				values := map[http2.SettingID]uint32{}
				sf.ForeachSetting(func(s http2.Setting) error { values[s.ID] = s.Val; return nil })
				return values
			}
		}
	}
	stock := read(listenGovernedXH(t, false, false, func(c stat.Connection) { c.Close() }))
	governed := read(listenGovernedXH(t, true, false, func(c stat.Connection) { c.Close() }))
	t.Logf("stock %v, governed %v", stock, governed)
	if governed[http2.SettingMaxFrameSize] != h2MinMaxFrameSize || governed[http2.SettingInitialWindowSize] != flowShownUp {
		t.Fatalf("governed server advertises %v, want the governor's frame size and initial window", governed)
	}
}

// TestFlowListenerClosesLikeStock (added for bdbac60e) sends an HTTP/1.1
// request whose headers exceed MaxHeaderBytes. net/http answers 431 and
// calls CloseWrite on the connection before it waits rstAvoidanceDelay, so
// with stock TLS the client sees close_notify right after the answer. The
// governed listener must close the same way.
func TestFlowListenerClosesLikeStock(t *testing.T) {
	closeAfter := func(addr string) time.Duration {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		tc := gotls.Client(raw, &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		io.WriteString(tc, "GET /shs/ HTTP/1.1\r\nHost: localhost\r\nX: "+strings.Repeat("a", 64<<10)+"\r\n\r\n")
		buf := make([]byte, 4096)
		var got []byte
		var first time.Time
		for {
			n, err := tc.Read(buf)
			if n > 0 && first.IsZero() {
				first = time.Now()
			}
			got = append(got, buf[:n]...)
			if err != nil {
				if !bytes.HasPrefix(got, []byte("HTTP/1.1 431")) {
					t.Fatalf("answer %q (%v)", got, err)
				}
				return time.Since(first)
			}
		}
	}
	stock := closeAfter(listenGovernedXH(t, false, false, func(c stat.Connection) { c.Close() }))
	governed := closeAfter(listenGovernedXH(t, true, false, func(c stat.Connection) { c.Close() }))
	t.Logf("end of stream after the 431: stock %v, governed %v", stock, governed)
	if governed > stock+250*time.Millisecond {
		t.Fatalf("governed listener ends the TLS stream %v after its answer, stock %v", governed, stock)
	}
}
