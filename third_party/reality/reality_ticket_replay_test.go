package reality

import (
	"container/list"
	"testing"
	"time"

	"github.com/xtls/reality/tls13"
)

// testTicket returns a ticket config issued for a TLS 1.3 session created
// at createdAt, and the shape it is offered under.
func testTicket(t *testing.T, config *Config, createdAt time.Time) ([]byte, *TicketShape) {
	t.Helper()
	state, err := (&SessionState{
		version: VersionTLS13, cipherSuite: TLS_AES_128_GCM_SHA256,
		createdAt: uint64(createdAt.Unix()), secret: make([]byte, 32),
	}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := config.encryptTicket(state, config.realityTicketKeys())
	if err != nil {
		t.Fatal(err)
	}
	return ticket, &TicketShape{Lifetime: 3600}
}

// A ticket from another process with the same private key, as before a
// restart or on another server, is unknown here: this process has no
// record of the hellos that resumed with it.
func TestTicketFromAnotherProcessIsUnknown(t *testing.T) {
	config := testConfig(t)
	salt := ticketKeySalt
	ticketKeySalt = make([]byte, 32)
	ticket, shape := testTicket(t, config, time.Now())
	ticketKeySalt = salt
	if config.realityTicketSession(shape, ticket, false) != nil {
		t.Fatal("a ticket another process issued was resumed")
	}
	ticket, shape = testTicket(t, config, time.Now())
	if config.realityTicketSession(shape, ticket, false) == nil {
		t.Fatal("this process's own ticket was not resumed")
	}
}

// Once the record of accepted hellos drops one to make room, a copy of it
// would be resumed again: tickets issued no later than a minute after its
// acceptance, the most the clock may have been stepped back by between the
// ticket and the hello, are not resumed from then on; newer ones still are.
func TestTicketHelloCacheForgetsOlderTickets(t *testing.T) {
	cache := &ticketHelloCache{size: 2, entries: make(map[[32]byte]*list.Element)}
	start := time.Now().Truncate(time.Second)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	ticketAt := func(seconds int) uint64 { return uint64(at(seconds).Unix()) }
	if !cache.remembers(ticketAt(-3600)) {
		t.Fatal("a cache that dropped nothing does not remember")
	}
	for i, key := range [][32]byte{{1}, {2}, {3}} {
		if !cache.accept(key, at(100*i), at(3600), true) {
			t.Fatalf("hello %d was refused", i)
		}
	}
	// The first hello, accepted at 0, is gone.
	if cache.remembers(ticketAt(-1)) || cache.remembers(ticketAt(0)) {
		t.Fatal("a ticket older than a dropped hello is still resumed")
	}
	if cache.remembers(ticketAt(60)) {
		t.Fatal("a ticket issued before a step back of the clock by a minute is still resumed")
	}
	if !cache.remembers(ticketAt(61)) {
		t.Fatal("a ticket newer than every dropped hello is not resumed")
	}
	// A hello not remembered drops nothing.
	if !cache.accept([32]byte{4}, at(300), at(3600), false) || !cache.remembers(ticketAt(61)) {
		t.Fatal("a hello that was not recorded forgot others")
	}
	if !cache.accept([32]byte{5}, at(400), at(3600), true) || cache.remembers(ticketAt(160)) || !cache.remembers(ticketAt(161)) {
		t.Fatal("dropping the hello accepted at 100 did not forget tickets up to a minute after it")
	}
}

// A copy of a resumed hello whose binder was checked while the hello was
// still recorded, and that is recorded itself once the hello was dropped,
// is not resumed: realityResume looks the ticket up again after that.
func TestTicketForgottenBeforeTheCopyIsRecorded(t *testing.T) {
	config := testConfig(t)
	cache := &ticketHelloCache{size: 2, entries: make(map[[32]byte]*list.Element)}
	previous := ticketHellos
	ticketHellos = cache
	t.Cleanup(func() { ticketHellos = previous })

	now := time.Now()
	issued := now.Add(-10 * time.Minute)
	ticket, shape := testTicket(t, config, issued)
	original, other, third := [32]byte{1}, [32]byte{2}, [32]byte{3}
	if !cache.accept(original, issued.Add(time.Second), now.Add(time.Hour), true) ||
		!cache.accept(other, now.Add(-5*time.Minute), now.Add(time.Hour), true) {
		t.Fatal("a hello was refused")
	}
	// The copy arrives: the ticket is known and its binder checked.
	if config.realityTicketSession(shape, ticket, false) == nil || config.resumableTicketSession(shape, ticket) == nil {
		t.Fatal("the ticket was not known while its hello was recorded")
	}
	// Another hello takes the original's place before the copy is recorded.
	if !cache.accept(third, now.Add(-4*time.Minute), now.Add(time.Hour), true) {
		t.Fatal("another hello was refused")
	}
	if !cache.accept(original, now, now.Add(time.Hour), true) {
		t.Fatal("the copy of a dropped hello was not recorded")
	}
	if config.resumableTicketSession(shape, ticket) != nil {
		t.Fatal("the copy of a dropped hello resumed")
	}
	// The ticket is still REALITY's: a wrong binder on it is refused as
	// before, as the target refuses its own.
	if config.realityTicketSession(shape, ticket, false) == nil {
		t.Fatal("a ticket older than a dropped hello is no longer known")
	}
	fresh, shape := testTicket(t, config, now)
	if config.resumableTicketSession(shape, fresh) == nil {
		t.Fatal("a ticket issued after the dropped hellos was not resumed")
	}
}

// resumingHandshake returns the server's state for a ClientHello that
// offers ticket with a valid binder, under a target profile that resumes,
// at the point realityResume decides.
func resumingHandshake(t *testing.T, config *Config, ticket []byte) *serverHandshakeStateTLS13 {
	t.Helper()
	ch := &clientHelloMsg{
		vers: VersionTLS12, random: make([]byte, 32), sessionId: make([]byte, 32),
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, compressionMethods: []uint8{compressionNone},
		supportedVersions: []uint16{VersionTLS13},
		keyShares:         []keyShare{{group: X25519, data: make([]byte, 32)}},
		pskModes:          []uint8{pskModeDHE},
		pskIdentities:     []pskIdentity{{label: ticket}},
		pskBinders:        [][]byte{make([]byte, 32)},
	}
	suite := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	earlySecret := tls13.NewEarlySecret(suite.hash.New, make([]byte, 32))
	helloBytes, err := ch.marshalWithoutBinders()
	if err != nil {
		t.Fatal(err)
	}
	transcript := suite.hash.New()
	transcript.Write(helloBytes)
	if err := ch.updateBinders([][]byte{suite.finishedHash(earlySecret.ResumptionBinderKey(), transcript)}); err != nil {
		t.Fatal(err)
	}
	hello := &serverHelloMsg{
		vers: VersionTLS12, random: make([]byte, 32), sessionId: make([]byte, 32),
		cipherSuite: TLS_AES_128_GCM_SHA256, supportedVersion: VersionTLS13,
		serverShare: keyShare{group: X25519, data: make([]byte, 32)},
	}
	if hello.original, err = hello.marshal(); err != nil {
		t.Fatal(err)
	}
	hs := &serverHandshakeStateTLS13{c: &Conn{config: config}, clientHello: ch, hello: hello, suite: suite}
	hs.c.out.handshakeLen[2] = 102
	return hs
}

// realityResume does not resume a ticket older than a hello the record
// dropped, though the ticket is REALITY's and the binder valid.
func TestRealityResumeSkipsForgottenTickets(t *testing.T) {
	config := testConfig(t)
	cache := &ticketHelloCache{size: 1, entries: make(map[[32]byte]*list.Element)}
	previous := ticketHellos
	ticketHellos = cache
	t.Cleanup(func() { ticketHellos = previous })
	shape := &TicketShape{
		Resumes: true, HelloDelta: 6, FlightRecords: 4, Lifetime: 3600,
		FullRecords: []int{41, 102, 58}, ResRecords: []int{37, 58},
	}

	now := time.Now()
	old, _ := testTicket(t, config, now.Add(-10*time.Minute))
	if hs := resumingHandshake(t, config, old); !hs.realityResume(shape) || !hs.c.didResume {
		t.Fatal("a ticket the record vouches for did not resume, so the test shows nothing")
	}
	for i, key := range [][32]byte{{1}, {2}} {
		if !cache.accept(key, now.Add(time.Duration(i-5)*time.Minute), now.Add(time.Hour), true) {
			t.Fatal("a hello was refused")
		}
	}
	if hs := resumingHandshake(t, config, old); hs.realityResume(shape) || hs.c.didResume || hs.usingPSK {
		t.Fatal("a ticket older than a hello the record dropped resumed")
	}
	fresh, _ := testTicket(t, config, now)
	if hs := resumingHandshake(t, config, fresh); !hs.realityResume(shape) || !hs.c.didResume {
		t.Fatal("a ticket newer than the hellos the record dropped did not resume")
	}
}
