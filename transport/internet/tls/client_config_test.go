package tls_test

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"sort"
	"strings"
	"testing"
	"testing/cryptotest"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/net"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/tls/hellotest"
	"github.com/xtls/xray-core/transport/internet/tls/refreshtest"
)

var certificateUsages = []xraytls.Certificate_Usage{
	xraytls.Certificate_ENCIPHERMENT,
	xraytls.Certificate_AUTHORITY_ISSUE,
}

// A dialer builds a TLS config per connection, and a client never selects a
// certificate through GetCertificate, so building one starts no refresh worker.
func TestGetClientTLSConfigStartsNoRefreshWorkers(t *testing.T) {
	for _, usage := range certificateUsages {
		t.Run(usage.String(), func(t *testing.T) {
			config, baseline := refreshtest.Config(t, usage)
			for range 3 {
				if config.GetClientTLSConfig().GetCertificate == nil {
					t.Fatal("the client config has no GetCertificate, which the server config has")
				}
			}
			if workers := refreshtest.Workers() - baseline; workers != 0 {
				t.Fatalf("three client configs started %d certificate refresh workers", workers)
			}
		})
	}
}

// A listener's config refreshes its certificates from the start, before its
// first handshake.
func TestGetTLSConfigRefreshesCertificatesAtOnce(t *testing.T) {
	for _, usage := range certificateUsages {
		t.Run(usage.String(), func(t *testing.T) {
			config, baseline := refreshtest.Config(t, usage)
			config.GetTLSConfig()
			if workers := refreshtest.Workers() - baseline; workers != 1 {
				t.Fatalf("a server config started %d certificate refresh workers, want 1", workers)
			}
		})
	}
}

// emitClientHelloWith sends the first ClientHello of config, through uTLS
// with fingerprint or through crypto/tls without one, under fixed randomness.
// A fingerprint whose hello cannot be built sends none and gives the error.
func emitClientHelloWith(t *testing.T, config *gotls.Config, fingerprint *utls.ClientHelloID, http11 bool) ([]byte, string) {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 1)
	capture := &hellotest.Capture{}
	var err error
	if fingerprint == nil {
		err = gotls.Client(capture, config).Handshake()
	} else {
		var options []xraytls.UClientOption
		if http11 {
			options = append(options, xraytls.WithHTTP11ALPN())
		}
		_, err = xraytls.ClientHandshake(context.Background(), capture, config, fingerprint, options...)
	}
	record, recordErr := capture.FirstRecord()
	if recordErr != nil {
		if err == nil {
			t.Fatal(recordErr)
		}
		return nil, err.Error()
	}
	return record, ""
}

// GetClientTLSConfig differs from GetTLSConfig only in the refresh workers it
// does not start: every dialer sends the same first ClientHello, byte for
// byte, with either, so SNI, ALPN and fingerprint are unchanged.
func TestGetClientTLSConfigSendsTheSameClientHello(t *testing.T) {
	if !hellotest.Isolated(t) {
		return
	}
	fingerprints := snapshotFingerprints(t)
	names := make([]string, 0, len(fingerprints)+1)
	for name := range fingerprints {
		names = append(names, name)
	}
	sort.Strings(names)
	names = append(names, "crypto/tls")

	dest := net.TCPDestination(net.DomainAddress("dest.example"), 443)
	paths := []struct {
		name    string
		options []xraytls.Option
		http11  bool
		modify  func(*xraytls.Config)
	}{
		{name: "destination", options: []xraytls.Option{xraytls.WithDestination(dest)}},
		{name: "serverName", options: []xraytls.Option{xraytls.WithDestination(dest)}, modify: func(c *xraytls.Config) {
			c.ServerName = "name.example"
		}},
		{name: "http11", http11: true, options: []xraytls.Option{xraytls.WithDestination(dest), xraytls.WithNextProto("http/1.1")}},
		{name: "alpn-resumption", options: []xraytls.Option{xraytls.WithDestination(dest)}, modify: func(c *xraytls.Config) {
			c.NextProtocol = []string{"h3"}
			c.EnableSessionResumption = true
		}},
		{name: "mitm", options: []xraytls.Option{xraytls.WithOverrideName("mitm.example")}},
	}
	for _, usage := range certificateUsages {
		for _, path := range paths {
			t.Run(usage.String()+"/"+path.name, func(t *testing.T) {
				config, _ := refreshtest.Config(t, usage)
				if path.modify != nil {
					path.modify(config)
				}
				for _, name := range names {
					t.Run(name, func(t *testing.T) {
						var fingerprint *utls.ClientHelloID
						if id, ok := fingerprints[name]; ok {
							fingerprint = &id
						}
						server, serverErr := emitClientHelloWith(t, config.GetTLSConfig(path.options...), fingerprint, path.http11)
						client, clientErr := emitClientHelloWith(t, config.GetClientTLSConfig(path.options...), fingerprint, path.http11)
						if !bytes.Equal(server, client) || serverErr != clientErr {
							t.Fatalf("the client config sends another ClientHello:\nGetTLSConfig:       %x %s\nGetClientTLSConfig: %x %s", server, serverErr, client, clientErr)
						}
						// only the *_psk forms build no hello, with either config
						if server == nil && !strings.Contains(name, "_psk") {
							t.Fatalf("no ClientHello was sent: %s", serverErr)
						}
					})
				}
			})
		}
	}
}
