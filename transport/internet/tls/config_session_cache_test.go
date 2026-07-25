package tls

import "testing"

func TestGetTLSConfigScopesClientSessionCache(t *testing.T) {
	firstConfig := &Config{EnableSessionResumption: true}
	secondConfig := &Config{EnableSessionResumption: true}

	firstCache := firstConfig.GetTLSConfig().ClientSessionCache
	if firstCache == nil {
		t.Fatal("session resumption enabled without a client session cache")
	}
	if got := firstConfig.GetTLSConfig().ClientSessionCache; got != firstCache {
		t.Fatal("the same TLS config did not reuse its session cache")
	}
	if got := secondConfig.GetTLSConfig().ClientSessionCache; got == firstCache {
		t.Fatal("different TLS configs shared a client session cache")
	}
}
