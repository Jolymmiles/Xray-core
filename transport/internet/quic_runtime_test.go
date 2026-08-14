package internet

import (
	"crypto/tls"
	"testing"

	quic "github.com/apernet/quic-go"
)

func TestPrepareQUICClientChromeParrotAndGSO(t *testing.T) {
	originalGetCertificate := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
	originalTLS := &tls.Config{GetCertificate: originalGetCertificate}

	tests := []struct {
		name           string
		params         *QuicParams
		wantChrome     bool
		wantZeroCID    bool
		wantDisableGSO bool
	}{
		{name: "default Chrome parrot", params: &QuicParams{}, wantChrome: true, wantZeroCID: true},
		{name: "explicit opt out and GSO opt out", params: &QuicParams{DisableChromeParrot: true, DisableGSO: true}, wantDisableGSO: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &quic.Config{}
			transport, clientTLS := PrepareQUICClient(nil, config, originalTLS, test.params)
			if config.ChromeParrot != test.wantChrome {
				t.Fatalf("ChromeParrot = %v, want %v", config.ChromeParrot, test.wantChrome)
			}
			_, zeroCID := transport.ConnectionIDGenerator.(quic.ZeroLengthConnectionIDGenerator)
			if zeroCID != test.wantZeroCID {
				t.Fatalf("zero-length CID = %v, want %v", zeroCID, test.wantZeroCID)
			}
			if transport.DisableGSO != test.wantDisableGSO {
				t.Fatalf("DisableGSO = %v, want %v", transport.DisableGSO, test.wantDisableGSO)
			}
			if originalTLS.GetCertificate == nil {
				t.Fatal("PrepareQUICClient mutated shared TLS config")
			}
			if test.wantChrome && clientTLS.GetCertificate != nil {
				t.Fatal("Chrome parrot TLS clone retained GetCertificate")
			}
			if !test.wantChrome && clientTLS.GetCertificate == nil {
				t.Fatal("opt-out TLS clone lost GetCertificate")
			}
		})
	}

	serverTransport := NewQUICTransport(nil, &QuicParams{DisableGSO: true})
	if !serverTransport.DisableGSO {
		t.Fatal("server transport did not propagate DisableGSO")
	}
}
