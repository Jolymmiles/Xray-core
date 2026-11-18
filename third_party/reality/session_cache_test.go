package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mldsa"
	"crypto/rand"
	"slices"
	"testing"
	"time"
)

func TestTicketKeysIncludeMLDSA(t *testing.T) {
	config := testConfig(t)
	without := config.Clone()
	var err error
	config.Mldsa65Key, err = mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	rotated := config.Clone()
	rotated.Mldsa65Key, err = mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("session state")
	ticket, err := config.encryptTicket(data, config.realityTicketKeys())
	if err != nil {
		t.Fatal(err)
	}
	cache := newSessionCache(10)
	cache.put(config, ticket, &SessionState{}, time.Minute)
	same := config.Clone()
	if !bytes.Equal(same.decryptTicket(ticket, same.realityTicketKeys()), data) || cache.get(same, ticket, false) == nil {
		t.Fatal("same authentication keys cannot open their ticket")
	}
	for _, different := range []*Config{without, rotated} {
		if different.decryptTicket(ticket, different.realityTicketKeys()) != nil || cache.get(different, ticket, false) != nil {
			t.Fatal("ticket survived an ML-DSA key change")
		}
	}
}

func TestResumeUsesMeasuredFlight(t *testing.T) {
	shape := TicketShape{Resumes: true, HelloDelta: 8, FlightRecords: 4, ResRecords: []int{31, 58, 90}}
	if shape.canResume() {
		t.Fatal("unexpected ServerHello delta permits resumption")
	}
	shape.HelloDelta = 6
	if !shape.canResume() || shape.resumedTicketRecordLength() != 0 {
		t.Fatal("a resumed flight without a ticket must clear the full handshake slot")
	}
	shape.ResTickets = 1
	if n := shape.resumedTicketRecordLength(); n != 90 {
		t.Fatalf("ticket record length = %d, want 90", n)
	}
}

func TestH2StartupKeepsUnclassifiedPostHandshakeRecords(t *testing.T) {
	hs := serverHandshakeStateTLS13{c: &Conn{h2Startup: []H2StartupRecord{{Length: 44}}}}
	original := []int{87, 49}
	lens, counts := hs.postHandshakeRecords(original)
	if !slices.Equal(lens, original) || !slices.Equal(counts, []int{0, 0}) {
		t.Fatalf("unknown ticket profile changed records: %v, %v", lens, counts)
	}
	hs.ticketShape = &TicketShape{Tickets: 1, TicketsPerRecord: 1}
	lens, counts = hs.postHandshakeRecords(original)
	if !slices.Equal(lens, []int{87}) || !slices.Equal(counts, []int{1}) {
		t.Fatalf("known ticket profile did not separate the H2 startup: %v, %v", lens, counts)
	}
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Config{PrivateKey: priv}
}

// A ticket that is an id belongs to the private key that issued it: a
// server with another key does not find it, even with the same id.
func TestSessionCacheIsScopedToTheKey(t *testing.T) {
	cache := newSessionCache(10)
	a, b := testConfig(t), testConfig(t)
	id := []byte("0123456789abcdef0123456789abcdef")
	cache.put(a, id, &SessionState{}, time.Minute)
	if cache.get(b, id, false) != nil {
		t.Fatal("another key finds the session")
	}
	if cache.get(a, id, false) == nil {
		t.Fatal("the key that issued it finds it")
	}
}

// Full, the cache drops its oldest session, without going over the rest.
func TestSessionCacheDropsTheOldest(t *testing.T) {
	cache := newSessionCache(2)
	a := testConfig(t)
	for _, id := range []string{"first", "second", "third"} {
		cache.put(a, []byte(id), &SessionState{}, time.Minute)
	}
	if cache.get(a, []byte("first"), false) != nil || cache.get(a, []byte("third"), false) == nil ||
		cache.order.Len() != 2 {
		t.Fatal("the oldest goes, the newest stays, the size holds")
	}
	cache.put(a, []byte("short"), &SessionState{}, -time.Second)
	if cache.get(a, []byte("short"), false) != nil {
		t.Fatal("an expired session is not found")
	}
}
