package proxy

import (
	"bytes"
	gotls "crypto/tls"
	stdnet "net"

	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// VisionCarrier concentrates the transport facts required by a VLESS Vision
// flow while leaving protocol timing with the inbound or outbound caller.
type VisionCarrier struct {
	connection    any
	tlsConnection any
	canSpliceCopy bool
}

// ResolveInboundVisionCarrier identifies only the carrier forms accepted by a
// VLESS inbound without reading or mutating their connection state.
func ResolveInboundVisionCarrier(connection stdnet.Conn, outer stat.Connection) VisionCarrier {
	if carrier, ok := resolveEncryptedVisionCarrier(connection, outer); ok {
		return carrier
	}
	carrier := VisionCarrier{canSpliceCopy: true}
	switch secureConnection := outer.(type) {
	case *xraytls.Conn:
		carrier.connection = secureConnection.Conn
		carrier.tlsConnection = secureConnection
	case *reality.Conn:
		carrier.connection = secureConnection.Conn
	}
	return carrier
}

// ResolveOutboundVisionCarrier identifies only the carrier forms accepted by a
// VLESS outbound without reading or mutating their connection state.
func ResolveOutboundVisionCarrier(connection stdnet.Conn, outer stat.Connection) VisionCarrier {
	if carrier, ok := resolveEncryptedVisionCarrier(connection, outer); ok {
		return carrier
	}
	carrier := VisionCarrier{canSpliceCopy: true}
	switch secureConnection := outer.(type) {
	case *xraytls.Conn:
		carrier.connection = secureConnection.Conn
		carrier.tlsConnection = secureConnection
	case *xraytls.UConn:
		carrier.connection = secureConnection.Conn
		carrier.tlsConnection = secureConnection
	case *reality.UConn:
		carrier.connection = secureConnection.Conn
	}
	return carrier
}

func resolveEncryptedVisionCarrier(connection stdnet.Conn, outer stat.Connection) (VisionCarrier, bool) {
	commonConnection, ok := connection.(*encryption.CommonConn)
	if !ok {
		return VisionCarrier{}, false
	}
	_, xorEncryption := commonConnection.Conn.(*encryption.XorConn)
	return VisionCarrier{
		connection:    commonConnection,
		canSpliceCopy: !xorEncryption && IsRAWTransportWithoutSecurity(outer),
	}, true
}

// Supported reports whether the connection is a recognized Vision carrier.
func (c VisionCarrier) Supported() bool {
	return c.connection != nil
}

// Buffers returns the carrier-owned TLS input buffers used by Vision's
// direct-copy transition.
func (c VisionCarrier) Buffers() (*bytes.Reader, *bytes.Buffer, bool) {
	if !c.Supported() {
		return nil, nil, false
	}
	return VisionBuffers(c.connection)
}

// InvalidTLSVersion reports the negotiated version when an ordinary TLS
// carrier violates Vision's existing TLS 1.3 gate. REALITY and VLESS
// encryption carriers retain their established validation behavior.
func (c VisionCarrier) InvalidTLSVersion() (uint16, bool) {
	var version uint16
	switch connection := c.tlsConnection.(type) {
	case *xraytls.Conn:
		version = connection.ConnectionState().Version
	case *xraytls.UConn:
		version = connection.ConnectionState().Version
	default:
		return 0, false
	}
	return version, version != gotls.VersionTLS13
}

// CanSpliceCopy reports whether the carrier remains eligible for Vision's
// raw direct-copy transition.
func (c VisionCarrier) CanSpliceCopy() bool {
	return c.canSpliceCopy
}
