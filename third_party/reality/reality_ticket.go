package reality

import (
	"bytes"
	"container/list"
	"crypto/aes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/xtls/reality/tls13"
)

// Reality specific file: session tickets in the shape of the target's.
//
// A client asks for tickets with realityTicketsFlag in the reserved byte of
// its encrypted session id; others get the empty records they always got.
// The tickets are encrypted with a key derived from the private key, so
// every server sharing the key accepts them, across restarts. A client that
// offers one seals its session id over the ClientHello with the binders
// zeroed, as the binders cover the session id.

// realityTicketsFlag is the bit of the session id's reserved byte by which
// a client asks for tickets.
const realityTicketsFlag = 1

// Keep the authenticated ClientHello keys in acceptance order. A duplicate
// refreshes neither the expiration nor the position of the entry.
type seenTicketHello struct {
	key     [32]byte
	expires time.Time
}

type ticketHelloCache struct {
	sync.Mutex
	size    int
	entries map[[32]byte]*list.Element
	order   list.List
}

var ticketHellos = ticketHelloCache{
	size:    sessionCacheSize,
	entries: make(map[[32]byte]*list.Element),
}

func (s *ticketHelloCache) accept(key [32]byte, now, expires time.Time, remember bool) bool {
	s.Lock()
	defer s.Unlock()
	if entry := s.entries[key]; entry != nil {
		if now.Before(entry.Value.(seenTicketHello).expires) {
			return false
		}
		s.order.Remove(entry)
		delete(s.entries, key)
	}
	if !remember {
		return true
	}
	if s.order.Len() == s.size {
		oldest := s.order.Front()
		delete(s.entries, oldest.Value.(seenTicketHello).key)
		s.order.Remove(oldest)
	}
	s.entries[key] = s.order.PushBack(seenTicketHello{key: key, expires: expires})
	return true
}

func (s *ticketHelloCache) acceptClientHello(hs *serverHandshakeStateTLS13, now time.Time, validBinder bool) bool {
	if !hs.c.realityTickets || len(hs.clientHello.pskBinders) == 0 {
		return true
	}
	// Hash the same transcript the selected binder covers, including the
	// restored session ID. Changing unselected binders cannot create a
	// new entry. Only a verified offer can add an entry.
	transcript, err := hs.clientHello.marshalWithoutBinders()
	if err != nil {
		return false
	}
	return s.accept(sha256.Sum256(transcript), now, now.Add(maxSessionTicketLifetime+time.Minute), validBinder)
}

// recordsKey is the key of GlobalPostHandshakeRecordsLens and
// GlobalTicketShapes for this ClientHello.
func recordsKey(config *Config, hello *clientHelloMsg) (key string, alpn int) {
	switch {
	case len(hello.alpnProtocols) == 0:
		alpn = 0
	case hello.alpnProtocols[0] == "h2":
		alpn = 2
	default:
		alpn = 1
	}
	return config.Dest + " " + hello.serverName + " " + strconv.Itoa(alpn), alpn
}

// pskAAD returns the additional data of the session id of a ClientHello
// that offers a ticket: the ClientHello with its binders zeroed.
func pskAAD(original []byte, binders [][]byte) []byte {
	n := 2
	for _, binder := range binders {
		n += 1 + len(binder)
	}
	aad := bytes.Clone(original)
	if n <= len(aad) {
		clear(aad[len(aad)-n:])
	}
	return aad
}

// ticketKeyMaterial includes every private key used to authenticate the
// full handshake. Adding, rotating, or removing ML-DSA invalidates tickets.
func (c *Config) ticketKeyMaterial() []byte {
	material := c.PrivateKey.Bytes()
	if c.Mldsa65Key != nil {
		material = append(material, c.Mldsa65Key.Bytes()...)
	}
	return material
}

// realityTicketKeys derives the session ticket key from the server's keys.
func (c *Config) realityTicketKeys() []ticketKey {
	if c.PrivateKey == nil {
		return nil
	}
	secret, err := hkdf.Key(sha256.New, c.ticketKeyMaterial(), nil, "REALITY session ticket", 32)
	if err != nil {
		return nil
	}
	return []ticketKey{c.ticketKeyFromBytes([32]byte(secret))}
}

// ticketMsgs returns n NewSessionTickets that together fill a record
// of recordLen bytes as the target's do: nonces as long as the target's and
// the tickets taking the rest, or nil if they cannot. For a target that
// never accepts its tickets back, REALITY's carry random bytes it never
// accepts either.
func (c *Conn) ticketMsgs(shape *TicketShape, recordLen, n int) [][]byte {
	if shape == nil || !shape.Issues {
		return nil
	}
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	keys := c.config.realityTicketKeys()
	if _, ok := c.out.cipher.(aead); suite == nil || !ok || c.resumptionSecret == nil || keys == nil || n < 1 {
		return nil
	}
	const fixed = 4 + 4 + 4 + 1 + 2 + 2 // type, length, lifetime, age_add, length prefixes
	room := (recordLen - recordHeaderLen - c.out.cipher.(aead).Overhead() - 1) / n
	ticketLen := room - fixed - shape.NonceLen
	if ticketLen < len(shape.Prefix)+1 {
		return nil
	}
	msgs := make([][]byte, 0, n)
	for range n {
		nonce := make([]byte, shape.NonceLen)
		ageAdd := make([]byte, 4)
		if _, err := io.ReadFull(c.config.rand(), nonce); err != nil {
			return nil
		}
		if _, err := io.ReadFull(c.config.rand(), ageAdd); err != nil {
			return nil
		}
		var label []byte
		if shape.Resumes {
			label = c.realityTicketLabel(suite, keys, shape.Prefix, nonce, ticketLen)
			if label == nil {
				// Too short to carry the session: an id of it, kept here,
				// as servers with a session cache issue (nginx with
				// ssl_session_tickets off).
				label = c.statefulTicket(suite, shape, nonce, ticketLen)
			}
		} else {
			label = make([]byte, ticketLen)
			copy(label, shape.Prefix)
			if _, err := io.ReadFull(c.config.rand(), label[len(shape.Prefix):]); err != nil {
				return nil
			}
		}
		if label == nil {
			return nil
		}
		m := &newSessionTicketMsgTLS13{
			lifetime: shape.Lifetime,
			ageAdd:   binary.LittleEndian.Uint32(ageAdd),
			nonce:    nonce,
			label:    label,
		}
		msg, err := m.marshal()
		if err != nil {
			return nil
		}
		msgs = append(msgs, msg)
	}
	return msgs
}

// realityTicketLabel returns a ticket of ticketLen bytes for this
// connection's session, sealed with REALITY's ticket key behind prefix.
func (c *Conn) realityTicketLabel(suite *cipherSuiteTLS13, keys []ticketKey, prefix, nonce []byte, ticketLen int) []byte {
	state := c.sessionState()
	state.secret = tls13.ExpandLabel(suite.hash.New, c.resumptionSecret, "resumption", nonce, suite.hash.Size())
	// An Extra entry pads the encrypted state to the length of the
	// target's tickets; the entry itself takes 3 bytes.
	base, err := state.Bytes()
	if err != nil {
		return nil
	}
	sealed := ticketLen - len(prefix)
	if pad := sealed - aes.BlockSize - sha256.Size - len(base); pad >= 3 {
		state.Extra = [][]byte{make([]byte, pad-3)}
	} else if pad != 0 {
		return nil
	}
	stateBytes, err := state.Bytes()
	if err != nil || aes.BlockSize+len(stateBytes)+sha256.Size != sealed {
		return nil
	}
	ticket, err := c.config.encryptTicket(stateBytes, keys)
	if err != nil {
		return nil
	}
	return append(bytes.Clone(prefix), ticket...)
}

// writeTicketRecord writes msgs as one handshake record of length bytes,
// after the handshake, the way the empty records of the target's lengths
// are.
func (c *Conn) writeTicketRecord(msgs [][]byte, length int) error {
	plainText := make([]byte, length-c.out.cipher.(aead).Overhead())
	content := bytes.Join(msgs, nil)
	if len(plainText) < recordHeaderLen+len(content)+1 {
		return errors.New("reality: tickets do not fit their record")
	}
	plainText[0] = byte(recordTypeApplicationData)
	plainText[1] = 3
	plainText[2] = 3
	binary.BigEndian.PutUint16(plainText[3:], uint16(length-recordHeaderLen))
	copy(plainText[recordHeaderLen:], content)
	plainText[recordHeaderLen+len(content)] = byte(recordTypeHandshake)
	record := c.out.cipher.(aead).Seal(plainText[:recordHeaderLen], c.out.seq[:], plainText[recordHeaderLen:], plainText[:recordHeaderLen])
	c.out.incSeq()
	_, err := c.write(record)
	return err
}

// realityResume accepts the ticket the client offers if REALITY issued it,
// and turns the handshake into a resumed one in the shape the target
// resumes its own tickets: a ServerHello with pre_shared_key and no
// certificate. Otherwise the handshake stays a full one, as with a target
// that does not know a ticket.
func (hs *serverHandshakeStateTLS13) realityResume(shape *TicketShape) bool {
	c := hs.c
	ch := hs.clientHello
	if !slices.Contains(ch.pskModes, pskModeDHE) || len(ch.pskIdentities) == 0 ||
		len(ch.pskIdentities) != len(ch.pskBinders) {
		return false
	}
	if !shape.canResume() {
		return false
	}
	// The target's live answer has the flight its probe had.
	if (shape.FlightRecords == 1) != (c.out.handshakeBuf != nil) || c.out.handshakeLen[2] == 0 {
		return false
	}
	session := c.config.realityTicketSession(shape, ch.pskIdentities[0].label, false)
	if session == nil {
		return false
	}
	pskSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if pskSuite == nil || pskSuite.hash != hs.suite.hash {
		return false
	}
	earlySecret, ok := checkBinder(pskSuite, session, ch)
	if !ok {
		return false
	}
	// EncryptedExtensions changes as the target's does: by as much as in
	// the probe, from the target's live answer to this ClientHello, which
	// may carry more (BoringSSL answers Chrome's ALPS in it). In a flight
	// of one record it shares it with the rest of the flight: what goes is
	// the certificate.
	ee := c.out.handshakeLen[2] + shape.ResRecords[0] - shape.FullRecords[0]
	if live := c.out.handshakeLen[2]; shape.FlightRecords == 1 && live-shape.FullRecords[0] >= -3 && live-shape.FullRecords[0] <= 3 {
		// The same answer as the probe's but for the signature, whose
		// length varies and which a resumed flight does not carry.
		ee = shape.ResRecords[0]
	}
	if ee <= recordHeaderLen {
		return false
	}
	hello, err := insertPSKExtension(hs.hello.original, shape.PSKIndex)
	if err != nil {
		return false
	}

	hs.hello.original = hello
	hs.hello.selectedIdentityPresent = true
	hs.hello.selectedIdentity = 0
	hs.earlySecret = earlySecret
	hs.usingPSK = true
	c.didResume = true
	c.out.handshakeLen[2] = ee
	c.out.handshakeLen[3] = 0
	c.out.handshakeLen[4] = 0
	if c.out.handshakeLen[6] != 0 {
		c.out.handshakeLen[6] = shape.resumedTicketRecordLength()
	}
	return true
}

func (shape *TicketShape) canResume() bool {
	return shape.Resumes && shape.HelloDelta == 6
}

func (shape *TicketShape) resumedTicketRecordLength() int {
	if shape.FlightRecords == 4 && shape.ResTickets > 0 && len(shape.ResRecords) > 2 {
		return shape.ResRecords[2]
	}
	return 0
}

// insertPSKExtension adds pre_shared_key, selecting the first identity, to
// a ServerHello handshake message at the index of the extensions.
func insertPSKExtension(hello []byte, index int) ([]byte, error) {
	offset, types, err := serverHelloExtensions(hello)
	if err != nil {
		return nil, err
	}
	if slices.Contains(types, extensionPreSharedKey) || index > len(types) {
		return nil, errors.New("reality: cannot add pre_shared_key")
	}
	at := offset + 2
	for range index {
		at += 4 + int(binary.BigEndian.Uint16(hello[at+2:]))
	}
	ext := []byte{0, byte(extensionPreSharedKey), 0, 2, 0, 0}
	out := make([]byte, 0, len(hello)+len(ext))
	out = append(out, hello[:at]...)
	out = append(out, ext...)
	out = append(out, hello[at:]...)
	msgLen := len(out) - 4
	out[1], out[2], out[3] = byte(msgLen>>16), byte(msgLen>>8), byte(msgLen)
	binary.BigEndian.PutUint16(out[offset:], uint16(len(out)-offset-2))
	return out, nil
}

// postHandshakeRecords returns the records to send after the client's
// Finished, given the target's after a full handshake, and how many
// tickets each of them carries.
func (hs *serverHandshakeStateTLS13) postHandshakeRecords(lens []int) ([]int, []int) {
	shape := hs.ticketShape
	tickets := make([]int, len(lens))
	if shape == nil {
		return lens, tickets
	}
	inFlight := 0
	if hs.ticketInFlight {
		inFlight = 1
	}
	total, perRecord := shape.Tickets-inFlight, shape.TicketsPerRecord
	if hs.usingPSK {
		flight := 2 + inFlight
		if shape.FlightRecords == 1 {
			flight = 1
		}
		lens = shape.ResRecords[min(flight, len(shape.ResRecords)):]
		tickets = make([]int, len(lens))
		total, perRecord = shape.ResTickets-inFlight, shape.ResTicketsPerRecord
	}
	count := 0
	for i := range tickets {
		if total <= 0 || perRecord < 1 {
			break
		}
		tickets[i] = min(perRecord, total)
		total -= tickets[i]
		count++
	}
	if len(hs.c.h2Startup) != 0 {
		// Only records identified by a ticket profile may be replaced
		// by the HTTP/2 startup profile.
		lens, tickets = lens[:count], tickets[:count]
	}
	return lens, tickets
}

// realityTicketSession returns the session in a ticket REALITY issued and
// that has not expired, or nil. A ticket that is an id of a session kept
// here is taken out when take is set; REALITY keeps them until they
// expire, as nginx's session cache does: a used one is still refused with
// a wrong binder there.
func (c *Config) realityTicketSession(shape *TicketShape, label []byte, take bool) *SessionState {
	if !bytes.HasPrefix(label, shape.Prefix) {
		return nil
	}
	var session *SessionState
	if plaintext := c.decryptTicket(label[len(shape.Prefix):], c.realityTicketKeys()); plaintext != nil {
		var err error
		if session, err = ParseSessionState(plaintext); err != nil {
			return nil
		}
	} else if session = statefulTickets.get(c, label, take); session == nil {
		return nil
	}
	if session.version != VersionTLS13 || session.isClient {
		return nil
	}
	age := c.time().Sub(time.Unix(int64(session.createdAt), 0))
	if age < -time.Minute || age > min(time.Duration(shape.Lifetime)*time.Second, maxSessionTicketLifetime) {
		return nil
	}
	return session
}

// checkBinder checks the binder of the first PSK identity of ch against
// session, and returns the early secret the session gives.
func checkBinder(suite *cipherSuiteTLS13, session *SessionState, ch *clientHelloMsg) (*tls13.EarlySecret, bool) {
	earlySecret := tls13.NewEarlySecret(suite.hash.New, session.secret)
	helloBytes, err := ch.marshalWithoutBinders()
	if err != nil {
		return nil, false
	}
	transcript := suite.hash.New()
	transcript.Write(helloBytes)
	return earlySecret, hmac.Equal(ch.pskBinders[0], suite.finishedHash(earlySecret.ResumptionBinderKey(), transcript))
}

// inspectTicketHello checks whether the offer authenticates a ticket we
// issued. For a known ticket with an invalid binder, it returns the
// target's measured refusal, when available.
func (hs *serverHandshakeStateTLS13) inspectTicketHello() (refusal *TicketShape, validBinder, invalidBinder bool) {
	ch := hs.clientHello
	if len(ch.pskIdentities) == 0 || len(ch.pskIdentities) != len(ch.pskBinders) ||
		!slices.Contains(ch.pskModes, pskModeDHE) {
		return nil, false, false
	}
	key, _ := recordsKey(hs.c.config, ch)
	shape := LoadTicketShape(key)
	if shape == nil || !shape.Resumes {
		return nil, false, false
	}
	session := hs.c.config.realityTicketSession(shape, ch.pskIdentities[0].label, false)
	if session == nil {
		return nil, false, false
	}
	suite := cipherSuiteTLS13ByID(session.cipherSuite)
	if suite == nil {
		return nil, false, false
	}
	if _, ok := checkBinder(suite, session, ch); ok {
		return nil, true, false
	}
	if shape.RefusesBadBinder {
		return shape, false, true
	}
	return nil, false, true
}

// statefulTicket returns a ticket of ticketLen bytes that is only an id of
// this connection's session, which REALITY keeps for the ticket's lifetime.
func (c *Conn) statefulTicket(suite *cipherSuiteTLS13, shape *TicketShape, nonce []byte, ticketLen int) []byte {
	if ticketLen < len(shape.Prefix)+16 {
		return nil // too short to be unguessable
	}
	label := make([]byte, ticketLen)
	copy(label, shape.Prefix)
	if _, err := io.ReadFull(c.config.rand(), label[len(shape.Prefix):]); err != nil {
		return nil
	}
	state := c.sessionState()
	state.secret = tls13.ExpandLabel(suite.hash.New, c.resumptionSecret, "resumption", nonce, suite.hash.Size())
	statefulTickets.put(c.config, label, state, time.Duration(shape.Lifetime)*time.Second)
	return label
}

// statefulTickets keeps the sessions of tickets that are ids, as a server's
// session cache does: in memory, until they expire, the oldest dropped when
// it is full. Entries belong to the private key that issued them: a server
// with another key does not find them.
var statefulTickets = newSessionCache(sessionCacheSize)

// sessionCacheSize bounds the sessions kept, as nginx's 10 MB cache of
// about 40000 does.
const sessionCacheSize = 40000

type sessionEntry struct {
	key     string
	state   *SessionState
	expires time.Time
}

type sessionCache struct {
	sync.Mutex
	size    int
	entries map[string]*list.Element
	order   list.List // oldest first
}

func newSessionCache(size int) *sessionCache {
	return &sessionCache{size: size, entries: make(map[string]*list.Element)}
}

// cacheKey scopes id to the full authentication policy of config.
func cacheKey(config *Config, id []byte) string {
	scope := sha256.Sum256(config.ticketKeyMaterial())
	return string(scope[:16]) + string(id)
}

func (s *sessionCache) put(config *Config, id []byte, state *SessionState, lifetime time.Duration) {
	s.Lock()
	defer s.Unlock()
	key := cacheKey(config, id)
	if e, ok := s.entries[key]; ok {
		s.order.Remove(e)
	}
	s.entries[key] = s.order.PushBack(&sessionEntry{key: key, state: state, expires: time.Now().Add(lifetime)})
	for s.order.Len() > s.size {
		oldest := s.order.Front()
		s.order.Remove(oldest)
		delete(s.entries, oldest.Value.(*sessionEntry).key)
	}
}

func (s *sessionCache) get(config *Config, id []byte, take bool) *SessionState {
	s.Lock()
	defer s.Unlock()
	key := cacheKey(config, id)
	e, ok := s.entries[key]
	if !ok {
		return nil
	}
	entry := e.Value.(*sessionEntry)
	expired := time.Now().After(entry.expires)
	if take || expired {
		s.order.Remove(e)
		delete(s.entries, key)
	}
	if expired {
		return nil
	}
	return entry.state
}
