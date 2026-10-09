package hysteria

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Hysteria 2.12.2 lets the masquerade proxy reach a Unix socket through an
// absolute path or a unix: URL, and rejects any other URL that is not HTTP(S)
// when the server starts. A URL that names no socket would otherwise answer
// every unauthenticated probe with 502 Bad Gateway instead of the site the
// server masquerades as.
func TestMasqueradeProxyURL(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"http://127.0.0.1:8080", true},
		{"https://example.com/base", true},
		{"unix:///run/site.sock", true},
		{"/run/site.sock", true},
		{"", false},
		{"run/site.sock", false},              // relative path
		{"example.com/site", false},           // a host without a scheme
		{"unix://run/site.sock", false},       // host
		{"unix:run/site.sock", false},         // relative opaque path
		{"unix://user@/run/site.sock", false}, // userinfo
		{"unix:///run/site.sock?x=1", false},  // query
		{"unix:///run/site.sock#x", false},    // fragment
		{"ftp://example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			settings := hysteriaTestSettings(t)
			settings.ProtocolSettings = &Config{Auth: "test", MasqType: "proxy", MasqUrl: tt.url}
			port := reserveHysteriaUDPPort(t)
			listener, err := Listen(context.Background(), xnet.LocalHostIP, xnet.Port(port), settings, func(stat.Connection) {})
			if listener != nil {
				_ = listener.Close()
			}
			if tt.valid && err != nil {
				t.Fatalf("Listen rejected masquerade proxy URL %q: %v", tt.url, err)
			}
			if !tt.valid && err == nil {
				t.Fatalf("Listen accepted masquerade proxy URL %q", tt.url)
			}
		})
	}
}

// An unauthenticated HTTP/3 request, as a prober sends, reaches the site behind
// the masquerade proxy's Unix socket with its path and Host intact.
func TestMasqueradeProxyServesUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "site.sock")
	backend, err := stdnet.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	site := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Site", "unix")
			_, _ = io.WriteString(w, r.Host+r.URL.Path)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = site.Serve(backend) }()
	t.Cleanup(func() { _ = site.Close() })

	for _, masqueradeURL := range []string{"unix://" + socketPath, socketPath} {
		t.Run(masqueradeURL, func(t *testing.T) {
			settings := hysteriaTestSettings(t)
			settings.ProtocolSettings = &Config{Auth: "test", MasqType: "proxy", MasqUrl: masqueradeURL}
			port := reserveHysteriaUDPPort(t)
			listener, err := Listen(context.Background(), xnet.LocalHostIP, xnet.Port(port), settings, func(stat.Connection) {})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			transport := &http3.Transport{TLSClientConfig: &gotls.Config{
				ServerName:         "localhost",
				InsecureSkipVerify: true, // #nosec G402 -- generated test certificate
				NextProtos:         []string{"h3"},
			}}
			defer transport.Close()
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			response, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/probe", port))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("127.0.0.1:%d/probe", port)
			if response.StatusCode != http.StatusOK || response.Header.Get("X-Site") != "unix" || string(body) != want {
				t.Fatalf("probe got %d %q from site %q, want 200 %q from the unix socket", response.StatusCode, body, response.Header.Get("X-Site"), want)
			}
		})
	}
}
