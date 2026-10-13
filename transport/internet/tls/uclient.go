package tls

import (
	"context"
	"crypto/tls"
	"net"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// Xray-core fork: every uTLS client Xray dials with is created and its
// ClientHello built here, so what that hello holds is decided in one place.

// UClientOption changes the ClientHello that UClient and NewUClient build.
type UClientOption func(*uClientOptions)

type uClientOptions struct {
	http11ALPN bool
}

// WithHTTP11ALPN gives the ClientHello the ALPN of the WebSocket and
// HTTPUpgrade transports: http/1.1, or h2 and http/1.1 when the config asks
// for exactly that to look like a browser. With ECH only the inner hello gets
// http/1.1 and the outer hello keeps the fingerprint's ALPN.
func WithHTTP11ALPN() UClientOption {
	return func(options *uClientOptions) {
		options.http11ALPN = true
	}
}

// NewUClient returns a uTLS client for c whose ClientHello is built: the
// fingerprint is applied and Xray's changes to it are made. The handshake
// sends this hello; REALITY seals its session ID into it first. When
// NewUClient fails the caller still owns c.
func NewUClient(c net.Conn, config *utls.Config, fingerprint utls.ClientHelloID, options ...UClientOption) (*utls.UConn, error) {
	return newUClient(c, config, fingerprint, clientSessionResumption{}, options)
}

// ClientHandshake creates the client of UClient and completes its handshake.
// It owns c from the start: on any failure c is closed.
func ClientHandshake(ctx context.Context, c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID, options ...UClientOption) (*UConn, error) {
	err := ctx.Err()
	var conn *UConn
	if err == nil {
		conn, err = UClient(c, config, fingerprint, options...)
	}
	if err == nil {
		err = conn.HandshakeContext(ctx)
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return conn, nil
}

// newUClient creates a uTLS client and builds its ClientHello. fingerprint
// is the one the caller selected, even when resumption applies it as a
// custom spec.
func newUClient(c net.Conn, config *utls.Config, fingerprint utls.ClientHelloID, resumption clientSessionResumption, options []UClientOption) (*utls.UConn, error) {
	var settings uClientOptions
	for _, option := range options {
		option(&settings)
	}
	// Read before the hello is built: applying a fingerprint replaces
	// config.NextProtos with the fingerprint's own ALPN.
	alpn := http11ALPN(config.NextProtos)

	uConn := resumption.client(c, config, fingerprint)
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	rebuild := false
	if settings.http11ALPN {
		if config.EncryptedClientHelloConfigList != nil {
			// The inner hello is marshaled from the config when it is sent.
			config.NextProtos = []string{"http/1.1"}
		} else {
			setALPN(uConn, alpn)
			rebuild = true
		}
	}
	if rebuild {
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, err
		}
	}
	return uConn, nil
}

// http11ALPN is the ALPN WithHTTP11ALPN sends for the requested one.
func http11ALPN(requested []string) []string {
	if slices.Equal(requested, []string{"h2", "http/1.1"}) {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

// setALPN makes the hello offer protocols. A fingerprint without ALPN gets
// the extension before pre_shared_key, which must stay the last extension
// (RFC 8446, Section 4.2.11).
func setALPN(uConn *utls.UConn, protocols []string) {
	for _, extension := range uConn.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = protocols
			return
		}
	}
	at := len(uConn.Extensions)
	for i, extension := range uConn.Extensions {
		if _, ok := extension.(utls.PreSharedKeyExtension); ok {
			at = i
			break
		}
	}
	uConn.Extensions = slices.Insert(uConn.Extensions, at, utls.TLSExtension(&utls.ALPNExtension{AlpnProtocols: protocols}))
}
