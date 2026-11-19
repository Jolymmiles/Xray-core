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

func TestRealityTicketRejectsMalformedLabels(t *testing.T) {
	config := testConfig(t)
	prefix := []byte{1, 2, 3, 4}
	shape := &TicketShape{Prefix: prefix, Lifetime: 60}
	invalidState, err := config.encryptTicket([]byte{0xff}, config.realityTicketKeys())
	if err != nil {
		t.Fatal(err)
	}
	for name, label := range map[string][]byte{
		"empty":         nil,
		"prefix only":   prefix,
		"short prefix":  prefix[:2],
		"short payload": append(bytes.Clone(prefix), 5),
		"invalid state": append(bytes.Clone(prefix), invalidState...),
		"unknown label": make([]byte, 192),
	} {
		t.Run(name, func(t *testing.T) {
			if config.realityTicketSession(shape, label, false) != nil {
				t.Fatal("a malformed label selected a resumable session")
			}
		})
	}
}

// Without a profile that places REALITY's tickets, a ticket REALITY sealed
// is found behind a prefix of any length, and nothing else is: not another
// key's, not an altered one, not one past the longest ticket lifetime, not
// one behind a prefix longer than any key name.
func TestUnprofiledTicketSession(t *testing.T) {
	config := testConfig(t)
	seal := func(config *Config, createdAt time.Time) []byte {
		t.Helper()
		state, err := (&SessionState{
			version: VersionTLS13, cipherSuite: TLS_AES_128_GCM_SHA256,
			createdAt: uint64(createdAt.Unix()), secret: make([]byte, 32),
		}).Bytes()
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := config.encryptTicket(state, config.realityTicketKeys())
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	sealed := seal(config, time.Now())
	for _, prefix := range [][]byte{nil, {1, 2, 3, 4}, bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{7}, maxUnprofiledTicketPrefix)} {
		if session := config.unprofiledTicketSession(slices.Concat(prefix, sealed)); session == nil || len(session.secret) != 32 {
			t.Fatalf("REALITY's ticket behind a prefix of %d bytes was not found", len(prefix))
		}
	}

	altered := slices.Concat([]byte{1, 2, 3, 4}, sealed)
	altered[len(altered)-1] ^= 1
	invalidState, err := config.encryptTicket([]byte{0xff}, config.realityTicketKeys())
	if err != nil {
		t.Fatal(err)
	}
	for name, label := range map[string][]byte{
		"empty":         nil,
		"short":         sealed[:47],
		"long prefix":   slices.Concat(bytes.Repeat([]byte{7}, maxUnprofiledTicketPrefix+1), sealed),
		"another key":   seal(testConfig(t), time.Now()),
		"altered":       altered,
		"expired":       seal(config, time.Now().Add(-maxSessionTicketLifetime-time.Hour)),
		"invalid state": invalidState,
		"unknown label": make([]byte, 192),
	} {
		t.Run(name, func(t *testing.T) {
			if config.unprofiledTicketSession(label) != nil {
				t.Fatal("a label REALITY did not seal, or that expired, gave a session")
			}
		})
	}
	if (&Config{}).unprofiledTicketSession(sealed) != nil {
		t.Fatal("a configuration without a private key found a ticket")
	}
}

// Xray always sets a private key, but direct users of the library reach
// ticket inspection before authentication without one.
func TestRealityTicketWithoutPrivateKey(t *testing.T) {
	config := &Config{}
	shape := &TicketShape{Lifetime: 60}
	if config.realityTicketSession(shape, make([]byte, 192), false) != nil {
		t.Fatal("a configuration without a private key resumed a ticket")
	}
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

// The cost of finding a ticket without a profile: a miss tries every prefix
// length up to the bound, over a label of a common ticket's length and over
// one of 4 KiB.
func BenchmarkUnprofiledTicketSession(b *testing.B) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	config := &Config{PrivateKey: priv}
	state, err := (&SessionState{
		version: VersionTLS13, cipherSuite: TLS_AES_128_GCM_SHA256,
		createdAt: uint64(time.Now().Unix()), secret: make([]byte, 32), Extra: [][]byte{make([]byte, 100)},
	}).Bytes()
	if err != nil {
		b.Fatal(err)
	}
	sealed, err := config.encryptTicket(state, config.realityTicketKeys())
	if err != nil {
		b.Fatal(err)
	}
	found := slices.Concat(bytes.Repeat([]byte{7}, 16), sealed)
	missed := make([]byte, len(found))
	b.Logf("label of %d bytes", len(found))
	b.Run("found", func(b *testing.B) {
		for b.Loop() {
			config.unprofiledTicketSession(found)
		}
	})
	b.Run("missed", func(b *testing.B) {
		for b.Loop() {
			config.unprofiledTicketSession(missed)
		}
	})
	long := make([]byte, 4<<10)
	b.Run("missed 4KiB", func(b *testing.B) {
		for b.Loop() {
			config.unprofiledTicketSession(long)
		}
	})
}
