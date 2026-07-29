package tls

import (
	"crypto/tls"
	"runtime"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The scope must key on the cache reference. A uintptr is not a GC root, so
// reverting this field lets an evicted cache be collected and its address
// reused, which silently merges two servers' ticket stores.
var _ tls.ClientSessionCache = uTLSSessionCacheScope{}.source

type nonComparableClientSessionCache []int

func (nonComparableClientSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	return nil, false
}

func (nonComparableClientSessionCache) Put(string, *tls.ClientSessionState) {}

// TestUTLSSessionCacheKeyRetainsSource guards FORK_DEFECTS_REVIEW item A.
func TestUTLSSessionCacheKeyRetainsSource(t *testing.T) {
	first := tls.NewLRUClientSessionCache(8)
	second := tls.NewLRUClientSessionCache(8)

	cacheA := uTLSSessionCache(first, utls.HelloChrome_Auto)
	cacheB := uTLSSessionCache(second, utls.HelloChrome_Auto)
	if cacheA == cacheB {
		t.Fatal("distinct session caches shared one uTLS cache")
	}
	if again := uTLSSessionCache(first, utls.HelloChrome_Auto); again != cacheA {
		t.Fatal("same session cache did not reuse its uTLS cache")
	}
	if sameSource := uTLSSessionCache(first, utls.HelloFirefox_Auto); sameSource == cacheA {
		t.Fatal("distinct fingerprints shared one uTLS cache")
	}

	// The entry outlives our references: the key holds the source, so the
	// address it occupies can never be handed to a different cache.
	runtime.GC()
	if again := uTLSSessionCache(first, utls.HelloChrome_Auto); again != cacheA {
		t.Fatal("uTLS cache lost after GC")
	}
	runtime.KeepAlive(second)
}

func TestCopyConfigSkipsNonComparableSessionCacheKey(t *testing.T) {
	source := nonComparableClientSessionCache{1}
	config, cacheSource := copyConfig(&tls.Config{ClientSessionCache: source})
	if cacheSource != nil {
		t.Fatal("non-comparable session cache was accepted as a map key")
	}
	if config.OmitEmptyPsk {
		t.Fatal("PSK extension enabled without a reusable uTLS session cache")
	}
}
