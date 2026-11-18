package reality

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

// Reality specific file: how the target issues and resumes TLS 1.3 session
// tickets, so that REALITY can issue and accept its own in the same shape.

// GlobalTicketShapes maps the key of GlobalPostHandshakeRecordsLens to the
// *TicketShape probed for it, or to false while the probe runs. A target
// without a usable shape maps to a *TicketShape with Resumes false.
var GlobalTicketShapes sync.Map

// TicketShape is what an observer sees of the target's session tickets.
type TicketShape struct {
	// Issues reports that the target issues tickets; the fields about them
	// are meaningful only when it is true. Resumes reports that it accepts
	// them back too, and the fields about resumed handshakes are meaningful
	// only then. Some targets issue tickets they never accept (servers
	// behind a load balancer without shared ticket keys): REALITY's then
	// carry nothing and are refused the same way.
	Issues  bool
	Resumes bool

	// FlightRecords is how many records carry the encrypted part of the
	// server's flight: 4, one per message (OpenSSL, crypto/tls), or 1
	// (BoringSSL). A resumed flight then has 2 records or 1.
	FlightRecords int
	// TicketsPerRecord and ResTicketsPerRecord are how many tickets share
	// the first record after the client's Finished, after a full and after
	// a resumed handshake: 1, or all of them (BoringSSL).
	TicketsPerRecord    int
	ResTicketsPerRecord int

	// TicketLen and ResTicketLen are the lengths of the target's tickets
	// after a full and after a resumed handshake, as clients send them back
	// in pre_shared_key. OpenSSL's grow with what the session holds.
	TicketLen    int
	ResTicketLen int
	// Prefix is what all of the target's tickets start with, such as the
	// key name OpenSSL puts first. Tickets that differ there would set
	// REALITY's apart from the target's.
	Prefix []byte
	// NonceLen is the length of the target's ticket_nonce. With it, the
	// length of a ticket follows from that of its record, which varies
	// with the target's tickets.
	NonceLen int
	// Lifetime is the ticket_lifetime the target announces, in seconds.
	Lifetime uint32
	// Tickets is the number of tickets after a full handshake.
	Tickets int
	// FullRecords are the encrypted records after the ServerHello of a full
	// handshake, lengths including headers: EncryptedExtensions,
	// Certificate, CertificateVerify, Finished, then what follows.
	FullRecords []int

	// HelloDelta is how much longer the ServerHello of a resumed handshake
	// is than that of a full one: the pre_shared_key extension.
	HelloDelta int
	// PSKIndex is the position of pre_shared_key among the extensions of
	// the target's ServerHello.
	PSKIndex int
	// ResRecords are the encrypted records after the ServerHello of a
	// resumed handshake: EncryptedExtensions, Finished, then the tickets,
	// either with the flight or after the client's Finished, and what
	// follows. Which of the two the target does shows in its live answer.
	ResRecords []int
	// ResTickets is the number of tickets after a resumed handshake.
	ResTickets int
	// BadBinder contains any TLS alerts from the refusal. A refusal can
	// also close the connection without TLS records.
	RefusesBadBinder bool
	BadBinder        []byte
	BadBinderDelay   time.Duration
	badBinderClose   refusalKind

	noTickets        bool
	probed           time.Time
	failedSince      time.Time
	badBinderSession *utls.ClientSessionState
}

// storeTicketShape stores shape for key, then probes how the target refuses
// a wrong binder, which may take long, and stores the shape again with it.
func storeTicketShape(config *Config, key, sni string, alpn int, shape *TicketShape) {
	shape.probed = time.Now()
	GlobalTicketShapes.Store(key, shape)
	if !shape.Resumes || shape.badBinderSession == nil {
		return
	}
	reply := confirmBinderRefusal(func() binderRefusal {
		return probeBadBinder(config, sni, alpn, shape.badBinderSession)
	})
	if reply.kind == noRefusal {
		return
	}
	refusing := *shape
	refusing.RefusesBadBinder = true
	refusing.BadBinder, refusing.BadBinderDelay, refusing.badBinderClose = reply.alerts, reply.delay, reply.kind
	refusing.badBinderSession = nil
	GlobalTicketShapes.CompareAndSwap(key, shape, &refusing)
}

// ticketRecordOverhead is what a TLS 1.3 record holding a NewSessionTicket
// adds to its nonce and ticket: the record header, the AEAD tag, the inner
// content type, and the message's type, length, lifetime, age_add and
// length prefixes.
const ticketRecordOverhead = recordHeaderLen + 16 + 1 + 4 + 4 + 4 + 1 + 2 + 2

const (
	ticketProbeTimeout = 10 * time.Second
	// ticketProbeWait is how long a probe reads after the handshake for the
	// tickets and other records the target sends without being asked.
	ticketProbeWait = 3 * time.Second
)

// DetectTicketShape probes the target once for key. DetectPostHandshakeRecordsLens
// starts it with the other probes, so that the first clients get tickets too.
func DetectTicketShape(config *Config, key, sni string, alpn int) {
	if _, loaded := GlobalTicketShapes.LoadOrStore(key, false); loaded {
		return
	}
	go func() {
		shape, err := probeTicketShape(config, sni, alpn)
		if shape == nil {
			shape = &TicketShape{noTickets: errors.Is(err, errNoTargetTickets)}
		}
		storeTicketShape(config, key, sni, alpn, shape)
	}()
}

// ticketShapeRefresh is how often the target is probed again: a target
// that restarts may get a new ticket key, and its tickets a new prefix.
const (
	ticketShapeRefresh = time.Hour
	ticketShapeMaxAge  = 3 * ticketShapeRefresh
)

var errNoTargetTickets = errors.New("reality: the target issues no tickets")

var refreshingTicketShapes sync.Map

// RefreshTicketShape probes the target again for key once the shape is
// older than ticketShapeRefresh. Start aging the profile at the first failed
// refresh so an idle inbound can use its last successful measurement.
func RefreshTicketShape(config *Config, key, sni string, alpn int) {
	val, _ := GlobalTicketShapes.Load(key)
	shape, ok := val.(*TicketShape)
	if !ok || time.Since(shape.probed) < ticketShapeRefresh {
		return
	}
	if _, busy := refreshingTicketShapes.LoadOrStore(key, struct{}{}); busy {
		return
	}
	// The preceding refresh may have finished since the first load.
	if current, _ := GlobalTicketShapes.Load(key); current != shape {
		refreshingTicketShapes.Delete(key)
		return
	}
	go func() {
		defer refreshingTicketShapes.Delete(key)
		fresh, err := probeTicketShape(config, sni, alpn)
		if err == nil {
			storeTicketShape(config, key, sni, alpn, fresh)
			return
		}
		now := time.Now()
		noTickets := errors.Is(err, errNoTargetTickets)
		if noTickets || shape.expired(now) {
			GlobalTicketShapes.Store(key, &TicketShape{probed: now, noTickets: noTickets})
			return
		}
		again := *shape
		again.probed = now
		if again.failedSince.IsZero() {
			again.failedSince = now
		}
		GlobalTicketShapes.Store(key, &again)
	}()
}

// LoadTicketShape returns the shape probed for key, or nil while the probe
// runs, when the target issues no tickets, or when the profile expired.
func LoadTicketShape(key string) *TicketShape {
	shape := loadTicketProfile(key)
	if shape == nil || !shape.Issues {
		return nil
	}
	return shape
}

// loadTicketProfile also returns successful measurements of targets that
// do not issue tickets, so HTTP/2 shaping can distinguish them from probes
// that have not completed.
func loadTicketProfile(key string) *TicketShape {
	val, ok := GlobalTicketShapes.Load(key)
	if !ok {
		return nil
	}
	shape, ok := val.(*TicketShape)
	if !ok || (!shape.Issues && !shape.noTickets) || shape.expired(time.Now()) {
		return nil
	}
	return shape
}

func (shape *TicketShape) expired(now time.Time) bool {
	return !shape.failedSince.IsZero() && now.Sub(shape.failedSince) >= ticketShapeMaxAge
}

// ticketRecorder is a ClientSessionCache that keeps every ticket put in it
// and hands out replay.
type ticketRecorder struct {
	sync.Mutex
	sessions []*utls.ClientSessionState
	replay   *utls.ClientSessionState
	overflow bool
}

func (r *ticketRecorder) Get(string) (*utls.ClientSessionState, bool) {
	r.Lock()
	defer r.Unlock()
	return r.replay, r.replay != nil
}

func (r *ticketRecorder) Put(_ string, cs *utls.ClientSessionState) {
	if cs == nil {
		return
	}
	r.Lock()
	defer r.Unlock()
	if len(r.sessions) < maxProbeTickets {
		r.sessions = append(r.sessions, cs)
	} else {
		r.overflow = true
	}
}

func (r *ticketRecorder) take() ([]*utls.ClientSessionState, bool) {
	r.Lock()
	defer r.Unlock()
	sessions := r.sessions
	r.sessions = nil
	return sessions, r.overflow
}

// probeCaptureConn records what the target sends.
const (
	maxProbeBytes   = 512 << 10
	maxProbeTickets = 32
)

var errProbeLimit = errors.New("reality: destination probe exceeded its byte limit")

type probeCaptureConn struct {
	net.Conn
	mu        sync.Mutex
	in        []byte
	firstByte time.Time
	readErr   error
	readEnd   time.Time
}

func (c *probeCaptureConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	if n > 0 && c.firstByte.IsZero() {
		c.firstByte = time.Now()
	}
	if n > maxProbeBytes-len(c.in) {
		err = errProbeLimit
		n = maxProbeBytes - len(c.in)
	}
	if err != nil {
		c.readErr = err
		c.readEnd = time.Now()
	}
	c.in = append(c.in, b[:n]...)
	c.mu.Unlock()
	return n, err
}

func (c *probeCaptureConn) received() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.in)
}

type probeRecord struct {
	typ  byte
	body []byte // without the header
}

func (r probeRecord) len() int { return recordHeaderLen + len(r.body) }

// splitRecords cuts b into TLS records; an incomplete last record is dropped.
func splitRecords(b []byte) []probeRecord {
	var records []probeRecord
	for len(b) >= recordHeaderLen {
		n := recordHeaderLen + int(binary.BigEndian.Uint16(b[3:5]))
		if n > len(b) {
			break
		}
		records = append(records, probeRecord{typ: b[0], body: b[recordHeaderLen:n]})
		b = b[n:]
	}
	return records
}

func recordLens(records []probeRecord) []int {
	lens := make([]int, 0, len(records))
	for _, r := range records {
		lens = append(lens, r.len())
	}
	return lens
}

// probeHandshake is one probe connection.
type probeHandshake struct {
	hello    probeRecord   // ServerHello
	records  []probeRecord // encrypted records after it
	resumed  bool
	sessions []*utls.ClientSessionState
}

func probeOnce(config *Config, sni string, alpn int, replay *utls.ClientSessionState) (*probeHandshake, error) {
	dial := config.DialContext
	if dial == nil {
		dial = new(net.Dialer).DialContext
	}
	ctx, cancel := context.WithTimeout(context.Background(), ticketProbeTimeout)
	defer cancel()
	target, err := dial(ctx, config.Type, config.Dest)
	if err != nil {
		return nil, err
	}
	defer target.Close()
	target.SetDeadline(time.Now().Add(ticketProbeTimeout))
	if config.Xver == 1 || config.Xver == 2 {
		if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
			return nil, err
		}
	}
	capture := &probeCaptureConn{Conn: target}
	recorder := &ticketRecorder{replay: replay}
	var nextProtos []string
	switch alpn {
	case 1:
		nextProtos = []string{"http/1.1"}
	case 2:
		nextProtos = []string{"h2", "http/1.1"}
	}
	uConn, err := probeClient(capture, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: sni == "",
		NextProtos:         nextProtos,
		ClientSessionCache: recorder,
	}, alpn, replay != nil)
	if err != nil {
		return nil, err
	}
	if err = uConn.Handshake(); err != nil {
		return nil, err
	}
	// Tickets are processed as they are read.
	if err := target.SetReadDeadline(time.Now().Add(ticketProbeWait)); err != nil {
		return nil, err
	}
	if _, err := io.Copy(io.Discard, uConn); err != nil {
		var readErr net.Error
		if !errors.As(err, &readErr) || !readErr.Timeout() {
			return nil, err
		}
	}
	if errors.Is(capture.readErr, errProbeLimit) {
		return nil, errProbeLimit
	}

	records := splitRecords(capture.received())
	if len(records) < 2 || records[0].typ != byte(recordTypeHandshake) {
		return nil, errors.New("reality: unexpected server flight")
	}
	sessions, overflow := recorder.take()
	if overflow {
		return nil, errProbeLimit
	}
	h := &probeHandshake{
		hello:    records[0],
		resumed:  uConn.ConnectionState().DidResume,
		sessions: sessions,
	}
	for _, r := range records[1:] {
		if r.typ == byte(recordTypeApplicationData) {
			h.records = append(h.records, r)
		}
	}
	return h, nil
}

// probeTicketShape does a full handshake with the target, then resumes it
// with the first ticket the target issued.
func probeTicketShape(config *Config, sni string, alpn int) (*TicketShape, error) {
	full, err := probeOnce(config, sni, alpn, nil)
	if err != nil {
		return nil, err
	}
	if len(full.sessions) == 0 {
		return nil, errNoTargetTickets
	}
	shape := &TicketShape{
		Tickets:     len(full.sessions),
		FullRecords: recordLens(full.records),
	}
	switch {
	case len(shape.FullRecords) >= 5 && shape.FullRecords[0] <= 512:
		shape.FlightRecords = 4
	case len(shape.FullRecords) >= 2 && shape.FullRecords[0] > 512:
		shape.FlightRecords = 1
	default:
		return nil, errors.New("reality: unsupported handshake records")
	}
	sessions := full.sessions
	res, err := probeOnce(config, sni, alpn, full.sessions[0])
	if err != nil {
		return nil, err
	}
	sessions = append(sessions, res.sessions...)
	if len(sessions) < 2 {
		// one more ticket shows what all of them start with
		if again, err := probeOnce(config, sni, alpn, nil); err == nil {
			sessions = append(sessions, again.sessions...)
		}
	}
	var tickets [][]byte
	for _, cs := range sessions {
		ticket, state, err := cs.ResumptionState()
		if err != nil || state == nil {
			return nil, errors.New("reality: unreadable ticket")
		}
		tickets = append(tickets, ticket)
		if lifetime, ok := ticketLifetime(state); ok && shape.Lifetime == 0 {
			shape.Lifetime = lifetime
		}
	}
	if shape.Lifetime == 0 {
		return nil, errors.New("reality: no ticket lifetime")
	}
	shape.TicketLen = len(tickets[0])
	shape.Prefix = commonPrefix(tickets)
	shortest := shape.TicketLen
	for _, ticket := range tickets {
		shortest = min(shortest, len(ticket))
	}
	if shape.TicketsPerRecord, shape.NonceLen, err = ticketLayout(shape.FullRecords[shape.FlightRecords:],
		shape.Tickets, shape.TicketLen, shortest); err != nil {
		return nil, err
	}
	shape.Issues = true

	if res.resumed {
		shape.ResTickets = len(res.sessions)
		shape.ResRecords = recordLens(res.records)
		shape.HelloDelta = res.hello.len() - full.hello.len()
		shape.ResTicketLen = shape.TicketLen
		if len(res.sessions) != 0 {
			shape.ResTicketLen = len(tickets[len(full.sessions)])
		}
		resFlight, ok := 1, len(shape.ResRecords) >= 1 && shape.ResRecords[0] <= 512
		if shape.FlightRecords == 4 {
			// the Finished of a full handshake is its fourth record, that
			// of a resumed one its second
			resFlight, ok = 2, len(shape.ResRecords) >= 2 && shape.FullRecords[3] == shape.ResRecords[1]
		}
		if !ok {
			return nil, errors.New("reality: unsupported resumed handshake records")
		}
		if shape.ResTickets != 0 {
			// A ticket sent with the flight (crypto/tls) is the first of
			// these; the target's live answer shows which it is.
			post := shape.ResRecords[resFlight:]
			if shape.ResTicketsPerRecord, _, err = ticketLayout(post, shape.ResTickets, shape.ResTicketLen, shortest); err != nil {
				return nil, err
			}
		}
		if shape.PSKIndex, err = pskExtensionIndex(res.hello.body); err != nil {
			return nil, err
		}
		shape.Resumes = true
	}
	shape.badBinderSession = full.sessions[0]
	return shape, nil
}

// ticketLayout tells, from the records after the client's Finished, how
// many tickets the first of them holds and the length of their nonce: one
// ticket per record when enough records can hold one, else all in the
// first (BoringSSL).
//
// ticketLen is the length of the first ticket, the first record's; the
// lengths of a target's tickets vary (OpenSSL's by 16 bytes), so whether a
// record can hold one is judged by the shortest, shortest.
func ticketLayout(post []int, tickets, ticketLen, shortest int) (perRecord, nonceLen int, err error) {
	fit := 0
	for _, l := range post {
		if l >= shortest+ticketRecordOverhead {
			fit++
		}
	}
	perRecord = 1
	if fit < tickets {
		perRecord = tickets
	}
	if len(post) == 0 {
		return 0, 0, errors.New("reality: tickets not where expected")
	}
	body := post[0] - (ticketRecordOverhead - (4 + 4 + 4 + 1 + 2 + 2)) // record header, tag, content type
	if body%perRecord != 0 {
		return 0, 0, errors.New("reality: tickets not where expected")
	}
	nonceLen = body/perRecord - (4 + 4 + 4 + 1 + 2 + 2) - ticketLen
	if nonceLen < 0 || nonceLen > 255 {
		return 0, 0, errors.New("reality: tickets not where expected")
	}
	return perRecord, nonceLen, nil
}

// ticketLifetime reads the lifetime a client session was given from its
// encoding, see SessionState.Bytes: created_at follows version, type and
// cipher_suite, use_by and age_add end a TLS 1.3 client session.
func ticketLifetime(state *utls.SessionState) (uint32, bool) {
	b, err := state.Bytes()
	if err != nil || len(b) < 5+8+12 || b[2] != 2 {
		return 0, false
	}
	createdAt := binary.BigEndian.Uint64(b[5:13])
	useBy := binary.BigEndian.Uint64(b[len(b)-12 : len(b)-4])
	if useBy <= createdAt {
		return 0, false
	}
	return uint32(useBy - createdAt), true
}

func commonPrefix(tickets [][]byte) []byte {
	if len(tickets) < 2 {
		return nil
	}
	prefix := tickets[0]
	for _, ticket := range tickets[1:] {
		n := 0
		for n < len(prefix) && n < len(ticket) && prefix[n] == ticket[n] {
			n++
		}
		prefix = prefix[:n]
	}
	// With two random tickets a single matching byte is unsurprising.
	// Retain only prefixes long enough to indicate a stable key identifier.
	if len(prefix) < 4 {
		return nil
	}
	return bytes.Clone(prefix)
}

// pskExtensionIndex finds pre_shared_key among the extensions of a
// ServerHello record body.
func pskExtensionIndex(hello []byte) (int, error) {
	types, err := serverHelloExtensionTypes(hello)
	if err != nil {
		return 0, err
	}
	for i, t := range types {
		if t == extensionPreSharedKey {
			return i, nil
		}
	}
	return 0, errors.New("reality: no pre_shared_key in the resumed ServerHello")
}

// serverHelloExtensions returns the offset of the extensions block of a
// ServerHello handshake message and the types in it.
func serverHelloExtensions(msg []byte) (offset int, types []uint16, err error) {
	// type(1) length(3) version(2) random(32)
	p := 4 + 2 + 32
	if len(msg) < p+1 || msg[0] != typeServerHello {
		return 0, nil, errors.New("reality: not a ServerHello")
	}
	p += 1 + int(msg[p]) // session id
	p += 2 + 1           // cipher suite, compression
	if len(msg) < p+2 {
		return 0, nil, errors.New("reality: short ServerHello")
	}
	offset = p
	end := p + 2 + int(binary.BigEndian.Uint16(msg[p:]))
	if end != len(msg) {
		return 0, nil, errors.New("reality: bad ServerHello extensions")
	}
	for p += 2; p < end; {
		if p+4 > end {
			return 0, nil, errors.New("reality: bad ServerHello extension")
		}
		types = append(types, binary.BigEndian.Uint16(msg[p:]))
		p += 4 + int(binary.BigEndian.Uint16(msg[p+2:]))
	}
	if p != end {
		return 0, nil, errors.New("reality: bad ServerHello extension")
	}
	return offset, types, nil
}

func serverHelloExtensionTypes(msg []byte) ([]uint16, error) {
	_, types, err := serverHelloExtensions(msg)
	return types, err
}

// binderSpoiler flips the last byte of the first record it writes: the end
// of the binders of a ClientHello that offers a ticket.
type binderSpoiler struct {
	net.Conn
	done   bool
	sentAt time.Time
}

func (c *binderSpoiler) Write(b []byte) (int, error) {
	if !c.done && len(b) > 0 && b[0] == byte(recordTypeHandshake) {
		c.done = true
		b = bytes.Clone(b)
		b[len(b)-1] ^= 1
		n, err := c.Conn.Write(b)
		if n == len(b) && err == nil {
			sentAt := time.Now()
			if err := c.SetReadDeadline(sentAt.Add(badBinderWait)); err != nil {
				return n, err
			}
			c.sentAt = sentAt
		}
		return n, err
	}
	return c.Conn.Write(b)
}

// badBinderWait is how long the probe of a wrong binder waits for the
// target's answer.
const badBinderWait = 40 * time.Second

type refusalKind uint8

const (
	noRefusal refusalKind = iota
	alertRefusal
	finRefusal
	resetRefusal
	silentRefusal
)

type binderRefusal struct {
	kind   refusalKind
	alerts []byte
	delay  time.Duration
}

func confirmBinderRefusal(probe func() binderRefusal) binderRefusal {
	reply := probe()
	if reply.kind == silentRefusal && probe().kind != silentRefusal {
		return binderRefusal{}
	}
	return reply
}

func connectionWasReset(err error) bool {
	// net.OpError wraps the Winsock errno on Windows.
	const wsaConnectionReset = syscall.Errno(10054)
	return errors.Is(err, syscall.ECONNRESET) ||
		(runtime.GOOS == "windows" && errors.Is(err, wsaConnectionReset))
}

func classifyBinderRefusal(capture *probeCaptureConn, start time.Time) binderRefusal {
	if errors.Is(capture.readErr, errProbeLimit) {
		return binderRefusal{}
	}
	answer := capture.received()
	if len(answer) == 0 {
		delay := capture.readEnd.Sub(start)
		switch err := capture.readErr; {
		case errors.Is(err, io.EOF):
			return binderRefusal{kind: finRefusal, delay: delay}
		case connectionWasReset(err):
			return binderRefusal{kind: resetRefusal, delay: delay}
		}
		var timeout net.Error
		if errors.As(capture.readErr, &timeout) && timeout.Timeout() && capture.readEnd.Sub(start) >= badBinderWait {
			return binderRefusal{kind: silentRefusal, delay: badBinderWait}
		}
		return binderRefusal{}
	}
	n := 0
	for _, r := range splitRecords(answer) {
		if r.typ != byte(recordTypeAlert) {
			return binderRefusal{}
		}
		n += r.len()
	}
	if n != len(answer) {
		return binderRefusal{}
	}
	return binderRefusal{kind: alertRefusal, alerts: answer, delay: refusalDelay(capture.firstByte.Sub(start))}
}

func refusalDelay(delay time.Duration) time.Duration {
	if delay < time.Second {
		return 0 // treat round-trip latency as an immediate refusal
	}
	return delay
}

// probeBadBinder measures the target's response after a complete write.
func probeBadBinder(config *Config, sni string, alpn int, session *utls.ClientSessionState) binderRefusal {
	dial := config.DialContext
	if dial == nil {
		dial = new(net.Dialer).DialContext
	}
	ctx, cancel := context.WithTimeout(context.Background(), ticketProbeTimeout)
	defer cancel()
	target, err := dial(ctx, config.Type, config.Dest)
	if err != nil {
		return binderRefusal{}
	}
	defer target.Close()
	if err := target.SetDeadline(time.Now().Add(ticketProbeTimeout)); err != nil {
		return binderRefusal{}
	}
	if config.Xver == 1 || config.Xver == 2 {
		if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
			return binderRefusal{}
		}
	}
	capture := &probeCaptureConn{Conn: target}
	var nextProtos []string
	switch alpn {
	case 1:
		nextProtos = []string{"http/1.1"}
	case 2:
		nextProtos = []string{"h2", "http/1.1"}
	}
	spoiler := &binderSpoiler{Conn: capture}
	uConn := utls.UClient(spoiler, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: sni == "",
		NextProtos:         nextProtos,
		ClientSessionCache: &ticketRecorder{replay: session},
	}, utls.HelloGolang)
	if err := uConn.Handshake(); err == nil || spoiler.sentAt.IsZero() {
		return binderRefusal{}
	}
	return classifyBinderRefusal(capture, spoiler.sentAt)
}

// probeClient returns the client of a probe: Chrome's ClientHello for the
// h2 key, as browsers send it there (a target may pick its certificate, and
// what it answers in EncryptedExtensions, by the ClientHello: Cloudflare
// sends Chrome an ECDSA chain, Go an RSA one), and Go's for the others,
// with pre_shared_key when it offers a ticket.
func probeClient(conn net.Conn, config *utls.Config, alpn int, offer bool) (*utls.UConn, error) {
	if alpn != 2 {
		return utls.UClient(conn, config, utls.HelloGolang), nil
	}
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return nil, err
	}
	if offer {
		spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
		config.OmitEmptyPsk = true // the ticket comes when the ClientHello is built
	}
	uConn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	return uConn, nil
}
