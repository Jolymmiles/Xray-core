package reality

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

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
