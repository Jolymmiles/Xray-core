package reality

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/net"
)

// Session resumption the way browsers do it: the second and later
// connections to a server offer a ticket the server issued, in a
// pre_shared_key extension, and resume with a short handshake.
//
// A REALITY server issues tickets only to clients that set
// realityTicketsFlag; older servers ignore the flag and issue none, so the
// client keeps doing full handshakes with them. Tickets are kept only from
// connections the client verified as REALITY, and each is used once, at most
// two per server, as Chrome keeps them. A resumed connection is verified by
// completing: only the server that issued the ticket knows its key.

// realityTicketsFlag is the bit of the session id's reserved byte by which
// the client asks for tickets, see github.com/xtls/reality.
const realityTicketsFlag = 1

const (
	ticketsPerServer = 2
	ticketServers    = 256
)

var tickets = &ticketStore{sessions: make(map[string][]*utls.ClientSessionState)}

// ticketBackoff is how long a client offers no ticket to a server after
// one failed there, as with a server of an older version behind the same
// address: it takes the ticket for a stranger's and hands the connection
// to the target. Tickets are still collected meanwhile.
const ticketBackoff = 10 * time.Minute

type ticketStore struct {
	sync.Mutex
	sessions map[string][]*utls.ClientSessionState
	failed   map[string]time.Time
}

// offer takes a ticket to offer to the server, unless one failed there
// lately.
func (s *ticketStore) offer(key string) *utls.ClientSessionState {
	s.Lock()
	if at, ok := s.failed[key]; ok {
		if time.Since(at) < ticketBackoff {
			s.Unlock()
			return nil
		}
		delete(s.failed, key)
	}
	s.Unlock()
	for {
		session := s.pop(key)
		if session == nil || usableTicket(session) {
			return session
		}
	}
}

// usableTicket is usable, but for tests of the store.
var usableTicket = usable

// usable reports whether uTLS will offer session: a TLS 1.3 session whose
// use-by time has not passed. The ClientHello is chosen by the ticket
// offered (Firefox's differs), so one uTLS would drop builds a resumption's
// ClientHello without its pre_shared_key.
func usable(session *utls.ClientSessionState) bool {
	_, state, err := session.ResumptionState()
	if err != nil || state == nil {
		return false
	}
	b, err := state.Bytes()
	// version, then the client's use_by and age_add end the encoding
	if err != nil || len(b) < 2+12 || binary.BigEndian.Uint16(b) != utls.VersionTLS13 {
		return false
	}
	useBy := time.Unix(int64(binary.BigEndian.Uint64(b[len(b)-12:])), 0)
	return time.Now().Before(useBy)
}

// fail drops the server's tickets and offers none to it for a while.
func (s *ticketStore) fail(key string) {
	s.Lock()
	defer s.Unlock()
	delete(s.sessions, key)
	if s.failed == nil {
		s.failed = make(map[string]time.Time)
	}
	if _, exists := s.failed[key]; !exists && len(s.failed) >= ticketServers {
		var oldest string
		var earliest time.Time
		for name, failedAt := range s.failed {
			if earliest.IsZero() || failedAt.Before(earliest) {
				oldest, earliest = name, failedAt
			}
		}
		delete(s.failed, oldest)
	}
	s.failed[key] = time.Now()
}

func (s *ticketStore) pop(key string) *utls.ClientSessionState {
	s.Lock()
	defer s.Unlock()
	list := s.sessions[key]
	if len(list) == 0 {
		return nil
	}
	session := list[len(list)-1]
	if len(list) == 1 {
		delete(s.sessions, key)
	} else {
		s.sessions[key] = list[:len(list)-1]
	}
	return session
}

func (s *ticketStore) push(key string, session *utls.ClientSessionState) {
	s.Lock()
	defer s.Unlock()
	list := s.sessions[key]
	if list == nil && len(s.sessions) >= ticketServers {
		for k := range s.sessions { // drop one server, whichever
			delete(s.sessions, k)
			break
		}
	}
	list = append(list, session)
	if len(list) > ticketsPerServer {
		list = list[len(list)-ticketsPerServer:]
	}
	s.sessions[key] = list
}

func (s *ticketStore) clear(key string) {
	s.Lock()
	defer s.Unlock()
	delete(s.sessions, key)
}

// connTickets is the ClientSessionCache of one connection. It holds the
// ticket the connection offers, taken from the store before the
// ClientHello is built, since the ClientHello depends on it; uTLS puts the
// tickets the server sends, and only those of a verified connection are
// kept.
type connTickets struct {
	key     string
	conn    *UConn
	session *utls.ClientSessionState
}

func (c *connTickets) Get(string) (*utls.ClientSessionState, bool) {
	session := c.session
	c.session = nil
	return session, session != nil
}

func (c *connTickets) Put(_ string, session *utls.ClientSessionState) {
	if session == nil {
		tickets.clear(c.key)
		return
	}
	if c.conn.Verified {
		tickets.push(c.key, session)
	}
}

// resumptionSpec returns the ClientHello of fingerprint as its browser
// sends it when it offers session, or nil when that is the ClientHello of
// fingerprint plus pre_shared_key, as with Chrome. Firefox drops the empty
// session_ticket extension, and sizes its GREASE ECH payload as if the
// inner ClientHello held the pre_shared_key too: it grows by the size of
// that extension rounded up to 32 bytes (Firefox 156 and 160 captures).
func resumptionSpec(fingerprint utls.ClientHelloID, session *utls.ClientSessionState) *utls.ClientHelloSpec {
	if fingerprint.Client != "Firefox" || session == nil {
		return nil
	}
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return nil
	}
	pskLen, ok := pskExtensionLen(session)
	if !ok {
		return nil
	}
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions))
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case utls.ISessionTicketExtension:
			continue
		case *utls.GREASEEncryptedClientHelloExtension:
			if len(e.CandidatePayloadLens) == 1 {
				e.CandidatePayloadLens = []uint16{e.CandidatePayloadLens[0] + uint16((pskLen+31)/32*32)}
			}
		}
		extensions = append(extensions, extension)
	}
	spec.Extensions = extensions
	return &spec
}

// pskExtensionLen is the size of the pre_shared_key extension offering
// session: type and length, the identity with its obfuscated age, and the
// binder, as long as the hash of the session's cipher suite.
func pskExtensionLen(session *utls.ClientSessionState) (int, bool) {
	ticket, state, err := session.ResumptionState()
	if err != nil || state == nil {
		return 0, false
	}
	b, err := state.Bytes()
	if err != nil || len(b) < 5 {
		return 0, false
	}
	binder := 32
	if uint16(b[3])<<8|uint16(b[4]) == utls.TLS_AES_256_GCM_SHA384 {
		binder = 48
	}
	return 4 + 2 + 2 + len(ticket) + 4 + 2 + 1 + binder, true
}

// ticketKey names the tickets of one REALITY server as one outbound sees it.
//
// The ML-DSA-65 key is part of it: a resumed handshake carries no
// certificate to check it against, so an outbound that requires it may only
// resume with tickets from handshakes that checked it.
func ticketKey(config *Config, dest net.Destination, serverName string) string {
	mldsa := sha256.Sum256(config.Mldsa65Verify)
	return dest.NetAddr() + " " + serverName + " " + hex.EncodeToString(config.PublicKey) + " " +
		hex.EncodeToString(config.ShortId) + " " + config.Fingerprint + " " + hex.EncodeToString(mldsa[:8])
}

// resumesSessions reports whether the browser of fingerprint resumes
// sessions: its ClientHello advertises session_ticket and
// psk_key_exchange_modes, so pre_shared_key belongs in it once a ticket is
// there. Randomized fingerprints have no browser to follow.
func resumesSessions(fingerprint utls.ClientHelloID) bool {
	if strings.HasPrefix(fingerprint.Client, "Randomized") {
		return false
	}
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return false
	}
	hasModes, hasTicket, hasTLS13 := false, false, false
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case utls.PreSharedKeyExtension:
			return false
		case *utls.PSKKeyExchangeModesExtension:
			hasModes = true
		case utls.ISessionTicketExtension:
			hasTicket = true
		case *utls.SupportedVersionsExtension:
			hasTLS13 = slices.Contains(e.Versions, utls.VersionTLS13)
		}
	}
	return hasModes && hasTicket && hasTLS13
}

// offeredPSK returns the pre_shared_key extension of the built ClientHello
// if it offers a ticket.
func offeredPSK(uConn *utls.UConn) *utls.UtlsPreSharedKeyExtension {
	for _, extension := range uConn.Extensions {
		if psk, ok := extension.(*utls.UtlsPreSharedKeyExtension); ok && len(psk.Identities) != 0 {
			return psk
		}
	}
	return nil
}

// pskAAD returns the additional data of the session id of a ClientHello
// that offers a ticket: the ClientHello with its binders zeroed, as the
// binders cover the session id.
func pskAAD(raw []byte, binders [][]byte) []byte {
	n := 2
	for _, binder := range binders {
		n += 1 + len(binder)
	}
	aad := bytes.Clone(raw)
	if n <= len(aad) {
		clear(aad[len(aad)-n:])
	}
	return aad
}

// verifyDelay returns how long the browser of fingerprint takes to verify
// a server's certificate chain, which REALITY's own check of the
// certificate does not take: the time between the server's flight and the
// client's Finished. Measured through REALITY in front of real sites
// (Microsoft, Cloudflare, Yandex, GitHub, CloudFront; 4-core x86-64 Linux):
// Chrome 157 15-48 ms, Edge 157 25-50 ms; Firefox 156 and 160 1-5 ms with
// the stand's short chain. Chromium keeps the result for the certificate
// for 30 minutes, and verifies again in about 1 ms meanwhile (GitHub, which
// refuses its tickets, shows it); the first verification after a browser
// starts takes about 125 ms and is not imitated. Resumed handshakes carry
// no certificate and get no delay, as in the browsers.
func verifyDelay(fingerprint utls.ClientHelloID, key string) func() time.Duration {
	var from, to time.Duration
	cached := false
	switch fingerprint.Client {
	case "Chrome":
		from, to, cached = 15*time.Millisecond, 48*time.Millisecond, true
	case "Edge":
		from, to, cached = 25*time.Millisecond, 50*time.Millisecond, true
	case "Firefox":
		from, to = 1*time.Millisecond, 5*time.Millisecond
	default:
		return nil
	}
	return func() time.Duration {
		if cached && !verifications.fresh(key) {
			return time.Millisecond
		}
		return from + time.Duration(rand.Int64N(int64(to-from)))
	}
}

// verifyCacheTTL is how long Chromium keeps a certificate's verification.
const verifyCacheTTL = 30 * time.Minute

var verifications = &verifyCache{at: make(map[string]time.Time)}

// verifyCache remembers when a server's certificate was last verified.
type verifyCache struct {
	sync.Mutex
	at map[string]time.Time
}

// fresh reports whether the certificate of the server named key needs a
// verification, a fresh one, and notes that it has one now.
func (v *verifyCache) fresh(key string) bool {
	v.Lock()
	defer v.Unlock()
	now := time.Now()
	last, ok := v.at[key]
	if !ok || now.Sub(last) > verifyCacheTTL {
		if len(v.at) >= ticketServers {
			clear(v.at)
		}
		v.at[key] = now
		return true
	}
	return false
}
