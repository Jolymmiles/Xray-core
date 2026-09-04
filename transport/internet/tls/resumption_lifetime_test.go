package tls

import (
	gotls "crypto/tls"
	"runtime"
	"testing"
	"weak"

	utls "github.com/refraction-networking/utls"
)

type lifetimeSessionCache struct {
	gotls.ClientSessionCache
}

func cacheScopeWeakReference() weak.Pointer[lifetimeSessionCache] {
	cache := &lifetimeSessionCache{gotls.NewLRUClientSessionCache(1)}
	resumption := newClientSessionResumption(&gotls.Config{ClientSessionCache: cache})
	resumption.sessionCache(utls.HelloChrome_Auto)
	return weak.Make(cache)
}

func TestResumptionScopeRetainsCacheIdentity(t *testing.T) {
	cache := cacheScopeWeakReference()
	runtime.GC()
	if cache.Value() == nil {
		t.Fatal("live uTLS scope lost its source cache; its address can identify another context")
	}
}
