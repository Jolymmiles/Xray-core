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

// randomizedWeights are the weights of the "randomized" and
// "randomizednoalpn" presets. uTLS offers X25519MLKEM768 in supported_groups
// (CurveIDs_Append_X25519, under TLS 1.3) and sends its key share
// (KeyShare_Append_RandomGroups) on two independent draws. The group without
// its key share makes a server that prefers it ask again, which uTLS cannot
// answer, and REALITY turns such a hello away; the key share without the
// group breaks RFC 8446, Section 4.2.8. Both are always drawn, as current
// browsers send them. The second weight also adds a P-256 key share, which
// newUClient removes. Do not change the weights once set: the presets are
// recognized by their address.
var randomizedWeights = func() utls.Weights {
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	weights.CurveIDs_Append_X25519 = 1
	weights.KeyShare_Append_RandomGroups = 1
	return weights
}()

// isRandomizedPreset reports whether fingerprint is one of Xray's randomized
// presets, a copy with another seed included. The raw hellorandomized*
// fingerprints are uTLS's own and keep uTLS's behavior.
func isRandomizedPreset(fingerprint utls.ClientHelloID) bool {
	return fingerprint.Weights == &randomizedWeights &&
		(fingerprint.Client == utls.HelloRandomizedALPN.Client || fingerprint.Client == utls.HelloRandomizedNoALPN.Client)
}

// UClientOption changes the ClientHello that UClient and NewUClient build.
type UClientOption func(*uClientOptions)

type uClientOptions struct {
	http11ALPN bool
	spec       *utls.ClientHelloSpec
}

func WithClientHelloSpec(spec *utls.ClientHelloSpec) UClientOption {
	return func(options *uClientOptions) {
		options.spec = spec
	}
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
// sends this hello; REALITY seals its session ID into it first. The client
// works on a copy of config, which uTLS would otherwise change while building
// the hello. When NewUClient fails the caller still owns c.
func NewUClient(c net.Conn, config *utls.Config, fingerprint utls.ClientHelloID, options ...UClientOption) (*utls.UConn, error) {
	return newUClient(c, config.Clone(), fingerprint, clientSessionResumption{}, options)
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
	if len(config.EncryptedClientHelloConfigList) > 0 && (settings.spec != nil || fingerprint != utls.HelloGolang) {
		// A ticket belongs in the inner hello, where uTLS cannot put it for
		// a fingerprint or a custom spec: it fails to build a hello that
		// offers one next to real ECH. HelloGolang alone is Go's own
		// client, which can.
		resumption = clientSessionResumption{}
		config.ClientSessionCache = nil
	}

	var uConn *utls.UConn
	switch {
	case settings.spec != nil:
		uConn = utls.UClient(c, config, utls.HelloCustom)
		if err := uConn.ApplyPreset(settings.spec); err != nil {
			return nil, err
		}
	case BuildsFirefoxClientHello(fingerprint, config.ServerName):
		if resumption.source != nil {
			config.ClientSessionCache = resumption.sessionCache(fingerprint)
		}
		var err error
		if uConn, err = newFirefoxClient(c, config, fingerprint); err != nil {
			return nil, err
		}
	default:
		uConn = resumption.client(c, config, fingerprint)
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	rebuild := false
	if isRandomizedPreset(fingerprint) {
		// X25519MLKEM768 and X25519 with keys of their own is what Chrome
		// sends. A third key share with its own key matches no browser:
		// Firefox sends P-256 as well but reuses the hybrid's X25519 key. A
		// server that wants P-256 asks for its key share.
		rebuild = dropKeyShare(uConn, utls.CurveP256)
	}
	if settings.http11ALPN {
		if config.EncryptedClientHelloConfigList != nil {
			// The inner hello is marshaled from the config when it is sent.
			config.NextProtos = []string{"http/1.1"}
		} else {
			setALPN(uConn, alpn)
			keepALPSWithinALPN(uConn, alpn)
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

// keepALPSWithinALPN leaves application settings only for protocols the
// hello offers, and no ALPS extension when none is left. Chromium adds ALPS
// for the protocols it puts in ALPN, and BoringSSL sends no extension
// without one, so a hello that offers http/1.1 alone carries no ALPS for h2.
func keepALPSWithinALPN(uConn *utls.UConn, alpn []string) {
	offered := func(protocols []string) []string {
		return slices.DeleteFunc(slices.Clone(protocols), func(protocol string) bool {
			return !slices.Contains(alpn, protocol)
		})
	}
	extensions := make([]utls.TLSExtension, 0, len(uConn.Extensions))
	for _, extension := range uConn.Extensions {
		switch settings := extension.(type) {
		case *utls.ApplicationSettingsExtension:
			settings.SupportedProtocols = offered(settings.SupportedProtocols)
			if len(settings.SupportedProtocols) == 0 {
				continue
			}
		case *utls.ApplicationSettingsExtensionNew:
			settings.SupportedProtocols = offered(settings.SupportedProtocols)
			if len(settings.SupportedProtocols) == 0 {
				continue
			}
		}
		extensions = append(extensions, extension)
	}
	uConn.Extensions = extensions
}

// dropKeyShare removes the key share for group from the hello and reports
// whether there was one.
func dropKeyShare(uConn *utls.UConn, group utls.CurveID) bool {
	for _, extension := range uConn.Extensions {
		if shares, ok := extension.(*utls.KeyShareExtension); ok {
			count := len(shares.KeyShares)
			shares.KeyShares = slices.DeleteFunc(shares.KeyShares, func(share utls.KeyShare) bool {
				return share.Group == group
			})
			return len(shares.KeyShares) != count
		}
	}
	return false
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
