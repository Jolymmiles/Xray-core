package tls

import (
	gotls "crypto/tls"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestClientSessionResumptionModuleScopesCaches(t *testing.T) {
	sharedStockCache := gotls.NewLRUClientSessionCache(1)
	first := newClientSessionResumption(&gotls.Config{ClientSessionCache: sharedStockCache})
	second := newClientSessionResumption(&gotls.Config{ClientSessionCache: sharedStockCache})
	other := newClientSessionResumption(&gotls.Config{ClientSessionCache: gotls.NewLRUClientSessionCache(1)})

	firstChrome := first.sessionCache(utls.HelloChrome_Auto)
	if got := second.sessionCache(utls.HelloChrome_Auto); got != firstChrome {
		t.Fatal("same stock cache and fingerprint produced different uTLS caches")
	}
	if got := first.sessionCache(utls.HelloEdge_Auto); got == firstChrome {
		t.Fatal("different fingerprints shared one uTLS cache")
	}
	if got := other.sessionCache(utls.HelloChrome_Auto); got == firstChrome {
		t.Fatal("different stock caches shared one uTLS cache")
	}
}

func TestClientSessionResumptionModuleActivation(t *testing.T) {
	cache := gotls.NewLRUClientSessionCache(1)
	enabled := newClientSessionResumption(&gotls.Config{ClientSessionCache: cache})
	if !enabled.enabled() {
		t.Fatal("resumption module ignored an enabled stock TLS cache")
	}

	disabled := newClientSessionResumption(&gotls.Config{
		ClientSessionCache:     cache,
		SessionTicketsDisabled: true,
	})
	if disabled.enabled() {
		t.Fatal("resumption module enabled a disabled stock TLS cache")
	}

	missing := newClientSessionResumption(&gotls.Config{})
	if missing.enabled() {
		t.Fatal("resumption module enabled without a stock TLS cache")
	}
}
