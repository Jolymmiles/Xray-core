package internet

import (
	"crypto/tls"
	stdnet "net"

	quic "github.com/apernet/quic-go"
)

// PrepareQUICClient applies Xray's QUIC client defaults without mutating a TLS
// configuration that may be shared by concurrent dials.
func PrepareQUICClient(conn stdnet.PacketConn, config *quic.Config, tlsConfig *tls.Config, params *QuicParams) (*quic.Transport, *tls.Config) {
	if params == nil {
		params = &QuicParams{}
	}
	config.ChromeParrot = !params.DisableChromeParrot
	transport := &quic.Transport{Conn: conn, DisableGSO: params.DisableGSO}
	clientTLS := tlsConfig.Clone()
	if config.ChromeParrot {
		transport.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
		clientTLS.GetCertificate = nil
	}
	return transport, clientTLS
}

// NewQUICTransport creates a server transport with config-controlled GSO.
func NewQUICTransport(conn stdnet.PacketConn, params *QuicParams) *quic.Transport {
	if params == nil {
		params = &QuicParams{}
	}
	return &quic.Transport{Conn: conn, DisableGSO: params.DisableGSO}
}
