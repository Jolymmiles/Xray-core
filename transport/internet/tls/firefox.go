package tls

import (
	"crypto/rand"
	"math"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Xray-core fork: Firefox's ClientHello is not one template. NSS sizes its
// GREASE ECH from the inner ClientHello it would encrypt, so the extension
// grows with the server name and with a pre_shared_key, and a Firefox that
// offers a TLS 1.3 ticket leaves session_ticket out. The rules below are
// measured on Firefox 156.0.1 and 160.0 (the 323 of 340 ClientHellos that
// carry no early_data, see testdata/firefox):
//
//	payload   = roundup32(117 + max(server name, 100) + pre_shared_key) + 16
//	extension = 42 + payload
//
// where pre_shared_key is that extension with its four-byte header, or 0.
// NSS pads the server name to 100 bytes (tls13_PadChInner) and the payload is
// its AEAD ciphertext; the encapsulated key is 32 pseudorandom bytes, not an
// X25519 public key (tls13_MaybeGreaseEch).

const (
	// nssInnerHelloLen is what Firefox 156's inner ClientHello takes without
	// its server name.
	nssInnerHelloLen = 117
	// nssServerNamePad is the length NSS pads a shorter server name to.
	nssServerNamePad      = 100
	nssEncapsulatedKeyLen = 32
)

// followsNSS reports whether fingerprint is the preset the rules above were
// measured for. The older Firefox presets keep their templates.
func followsNSS(fingerprint utls.ClientHelloID) bool {
	return fingerprint.Client == utls.HelloFirefox_156.Client && fingerprint.Version == utls.HelloFirefox_156.Version
}

// BuildsFirefoxClientHello reports whether NewUClient and UClient build the
// ClientHello of fingerprint for serverName as Firefox sends it, from the
// ticket in the session cache of the config: a preset that followsNSS and a
// name that goes into server_name. A connection to an IP address sends no
// server_name, which was not measured, and keeps the template.
func BuildsFirefoxClientHello(fingerprint utls.ClientHelloID, serverName string) bool {
	return followsNSS(fingerprint) && serverNameExtension(serverName) != ""
}

// firefoxClientHello returns the ClientHello that the Firefox of fingerprint
// sends to serverName when it offers session, or sends without a session when
// session is nil. BuildsFirefoxClientHello holds for its arguments.
func firefoxClientHello(fingerprint utls.ClientHelloID, serverName string, session *utls.ClientSessionState) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return nil, err
	}
	pskLen := 0
	if session != nil && session.Vers() == utls.VersionTLS13 {
		pskLen = preSharedKeyLen(session)
	}
	encapsulatedKey := make([]byte, nssEncapsulatedKeyLen)
	if _, err := rand.Read(encapsulatedKey); err != nil {
		return nil, err
	}
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case utls.ISessionTicketExtension:
			if pskLen != 0 {
				continue
			}
		case *utls.GREASEEncryptedClientHelloExtension:
			e.EncapsulatedKey = encapsulatedKey
			e.CandidatePayloadLens = []uint16{nssInnerHelloPaddedLen(len(serverNameExtension(serverName)), pskLen)}
		}
		extensions = append(extensions, extension)
	}
	if pskLen != 0 {
		// pre_shared_key is the last extension (RFC 8446, Section 4.2.11).
		extensions = append(extensions, &utls.UtlsPreSharedKeyExtension{})
	}
	spec.Extensions = extensions
	return &spec, nil
}

// nssInnerHelloPaddedLen is the length of the inner ClientHello NSS would
// encrypt, padded to 32 bytes: what the GREASE ECH payload holds before its
// AEAD tag. A ticket too long for the length field gives the largest value,
// and a ClientHello that does not fit, which newFirefoxClient turns down.
func nssInnerHelloPaddedLen(serverNameLen, pskLen int) uint16 {
	return uint16(min((nssInnerHelloLen+max(serverNameLen, nssServerNamePad)+pskLen+31)/32*32, math.MaxUint16/32*32))
}

// preSharedKeyLen is the size of the pre_shared_key extension that offers
// session: type and length, one identity with its obfuscated age, and one
// binder as long as the hash of the session's cipher suite.
func preSharedKeyLen(session *utls.ClientSessionState) int {
	binder := 32
	if session.CipherSuite() == utls.TLS_AES_256_GCM_SHA384 {
		binder = 48
	}
	return 4 + 2 + 2 + len(session.SessionTicket()) + 4 + 2 + 1 + binder
}

// serverNameExtension is the host name uTLS sends in server_name for a
// config's ServerName, or "" when it sends none: an IP address is not sent,
// and trailing dots are dropped (RFC 6066, Section 3).
func serverNameExtension(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return strings.TrimRight(name, ".")
}

// offersPreSharedKey reports whether the built ClientHello offers a ticket in
// pre_shared_key.
func offersPreSharedKey(uConn *utls.UConn) bool {
	for _, extension := range uConn.Extensions {
		if psk, ok := extension.(*utls.UtlsPreSharedKeyExtension); ok && len(psk.Identities) != 0 {
			return true
		}
	}
	return false
}

// offeredSession is the session cache of one connection whose ClientHello
// depends on the ticket it offers. The ticket is taken from the store before
// the ClientHello is built; the tickets the server sends go to the store.
type offeredSession struct {
	session *utls.ClientSessionState
	store   utls.ClientSessionCache
}

func (o *offeredSession) Get(string) (*utls.ClientSessionState, bool) {
	session := o.session
	o.session = nil
	return session, session != nil
}

func (o *offeredSession) Put(key string, session *utls.ClientSessionState) {
	o.store.Put(key, session)
}

// newFirefoxClient creates the uTLS client of a fingerprint and server name
// for which BuildsFirefoxClientHello holds, and builds its ClientHello. The ticket in the
// session cache of config, if there is one, decides the ClientHello, so it is
// taken first. A ticket uTLS then declines to offer leaves the ClientHello of
// a first connection.
func newFirefoxClient(c net.Conn, config *utls.Config, fingerprint utls.ClientHelloID) (*utls.UConn, error) {
	var session *utls.ClientSessionState
	store := config.ClientSessionCache
	if store != nil && !config.SessionTicketsDisabled {
		session = takeSession(store, sessionCacheKey(c, config))
	}
	// A ticket uTLS does not offer leaves pre_shared_key out.
	config.OmitEmptyPsk = true
	for {
		spec, err := firefoxClientHello(fingerprint, config.ServerName, session)
		if err != nil {
			return nil, err
		}
		if store != nil {
			config.ClientSessionCache = &offeredSession{session: session, store: store}
		}
		uConn := utls.UClient(c, config, utls.HelloCustom)
		if err := uConn.ApplyPreset(spec); err != nil {
			return nil, err
		}
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, err
		}
		if session == nil {
			return uConn, nil
		}
		// A server chooses the size of its ticket, and Firefox's ClientHello
		// carries a TLS 1.3 ticket's length twice, in pre_shared_key and in
		// the GREASE ECH: past some 31 KB the extensions outgrow their
		// two-byte length and uTLS writes a hello no server can parse.
		offered := session.Vers() != utls.VersionTLS13 || offersPreSharedKey(uConn)
		if offered && extensionsFit(uConn) {
			return uConn, nil
		}
		// Otherwise uTLS turned the ticket down (expired, another
		// certificate chain), and the hello above lacks both session_ticket
		// and pre_shared_key. Either way the connection starts afresh.
		session = nil
	}
}

// extensionsFit reports whether the extensions of the built ClientHello fit
// the two-byte length that precedes them.
func extensionsFit(uConn *utls.UConn) bool {
	total := 0
	for _, extension := range uConn.Extensions {
		total += extension.Len()
	}
	return total <= math.MaxUint16
}

// takeSession asks store for the session a connection may offer. Firefox
// uses a ticket once, and Xray's caches give a ticket up when asked for it:
// the one behind the TLS settings and REALITY's. A cache a caller of
// NewUClient brings keeps its own policy, as it does for any fingerprint;
// taking the ticket out of it here could not be made safe against its other
// users.
func takeSession(store utls.ClientSessionCache, key string) *utls.ClientSessionState {
	session, ok := store.Get(key)
	if !ok {
		return nil
	}
	return session
}

// sessionCacheKey is the key uTLS looks a session up by.
func sessionCacheKey(c net.Conn, config *utls.Config) string {
	if config.ServerName != "" {
		return config.ServerName
	}
	if c != nil && c.RemoteAddr() != nil {
		return c.RemoteAddr().String()
	}
	return ""
}
