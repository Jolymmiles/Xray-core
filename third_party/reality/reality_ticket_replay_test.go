package reality

import (
	"container/list"
	"testing"
	"time"
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
// would be resumed again: tickets issued no later than its acceptance are
// unknown from then on, and newer ones still resume.
func TestTicketHelloCacheForgetsOlderTickets(t *testing.T) {
	cache := &ticketHelloCache{size: 2, entries: make(map[[32]byte]*list.Element)}
	start := time.Now().Truncate(time.Second)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	ticketAt := func(seconds int) uint64 { return uint64(at(seconds).Unix()) }
	if !cache.remembers(ticketAt(-3600)) {
		t.Fatal("a cache that dropped nothing does not remember")
	}
	for i, key := range [][32]byte{{1}, {2}, {3}} {
		if !cache.accept(key, at(10*i), at(3600), true) {
			t.Fatalf("hello %d was refused", i)
		}
	}
	// The first hello, accepted at 0, is gone.
	if cache.remembers(ticketAt(-1)) || cache.remembers(ticketAt(0)) {
		t.Fatal("a ticket older than a dropped hello is still resumed")
	}
	if !cache.remembers(ticketAt(1)) {
		t.Fatal("a ticket newer than every dropped hello is not resumed")
	}
	// A hello not remembered drops nothing.
	if !cache.accept([32]byte{4}, at(30), at(3600), false) || !cache.remembers(ticketAt(1)) {
		t.Fatal("a hello that was not recorded forgot others")
	}
	if !cache.accept([32]byte{5}, at(40), at(3600), true) || cache.remembers(ticketAt(10)) || !cache.remembers(ticketAt(11)) {
		t.Fatal("dropping the hello accepted at 10 did not forget tickets up to it")
	}
}

// A copy of a resumed hello whose binder was checked while the hello was
// still recorded, and that is recorded itself once the hello was dropped,
// is not resumed: the handshake looks the ticket up again after that.
func TestTicketForgottenBeforeTheCopyIsRecorded(t *testing.T) {
	config := testConfig(t)
	cache := &ticketHelloCache{size: 1, entries: make(map[[32]byte]*list.Element)}
	previous := ticketHellos
	ticketHellos = cache
	t.Cleanup(func() { ticketHellos = previous })

	issued := time.Now().Add(-time.Minute)
	ticket, shape := testTicket(t, config, issued)
	original, copied, other := [32]byte{1}, [32]byte{1}, [32]byte{2}
	if !cache.accept(original, issued.Add(time.Second), issued.Add(time.Hour), true) {
		t.Fatal("the original hello was refused")
	}
	// The copy arrives: the ticket is known and its binder checked.
	if config.realityTicketSession(shape, ticket, false) == nil {
		t.Fatal("the ticket was not known while its hello was recorded")
	}
	// Another hello takes the original's place before the copy is recorded.
	if !cache.accept(other, time.Now(), time.Now().Add(time.Hour), true) {
		t.Fatal("another hello was refused")
	}
	if !cache.accept(copied, time.Now(), time.Now().Add(time.Hour), true) {
		t.Fatal("the copy of a dropped hello was not recorded")
	}
	// realityResume looks the ticket up again.
	if config.realityTicketSession(shape, ticket, false) != nil {
		t.Fatal("the copy of a dropped hello resumed")
	}
	fresh, shape := testTicket(t, config, time.Now().Add(time.Second))
	if config.realityTicketSession(shape, fresh, false) == nil {
		t.Fatal("a ticket issued after the dropped hello was not resumed")
	}
}
