// Package refreshtest counts the certificate refresh workers a TLS config
// starts. It is for tests only.
package refreshtest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Workers is the number of certificate refresh workers running in the process.
func Workers() int {
	stack := make([]byte, 1<<20)
	for {
		n := runtime.Stack(stack, true)
		if n < len(stack) {
			return strings.Count(string(stack[:n]), "transport/internet/tls.setupOcspTicker.func1()")
		}
		stack = make([]byte, 2*len(stack))
	}
}

// Config is a TLS config with one certificate of usage, read from files, that
// GetTLSConfig starts a refresh worker for. It returns the config and the
// number of workers running before it. The workers stop once its files are
// removed, which the cleanup does and waits for.
func Config(t *testing.T, usage tls.Certificate_Usage) (*tls.Config, int) {
	t.Helper()
	var options []cert.Option
	if usage == tls.Certificate_AUTHORITY_ISSUE {
		options = append(options, cert.Authority(true))
	}
	options = append(options, cert.DNSNames("dns.example"))
	certificate, _ := cert.MustGenerate(nil, options...)
	certPEM, keyPEM := certificate.ToPEM()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	baseline := Workers()
	t.Cleanup(func() {
		os.Remove(certPath)
		os.Remove(keyPath)
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for Workers() > baseline {
			select {
			case <-tick.C:
			case <-deadline.C:
				t.Error("certificate refresh workers did not stop after their files were removed")
				return
			}
		}
	})
	return &tls.Config{Certificate: []*tls.Certificate{{
		Certificate: certPEM, Key: keyPEM, Usage: usage,
		CertificatePath: certPath, KeyPath: keyPath, OcspStapling: 1,
	}}}, baseline
}
