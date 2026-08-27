package conf

import (
	"encoding/json"
	"testing"
)

func TestXdnsBuildValidation(t *testing.T) {
	c := &Xdns{}
	if _, err := c.Build(); err == nil {
		t.Fatal("empty domains & resolvers must be rejected")
	}

	removed := &Xdns{Domain: json.RawMessage("legacy.example")}
	if _, err := removed.Build(); err == nil {
		t.Fatal("removed 'domain' key must keep failing")
	}

	badResolver := &Xdns{Resolvers: []string{"t.example"}}
	if _, err := badResolver.Build(); err == nil {
		t.Fatal("resolver without +udp:// scheme must be rejected at build time")
	}

	badHost := &Xdns{Resolvers: []string{"t.example+udp://not-an-ip:53"}}
	if _, err := badHost.Build(); err == nil {
		t.Fatal("resolver with non-IP host must be rejected at build time")
	}

	badMethod := &Xdns{Domains: []string{"t.example:bogus"}}
	if _, err := badMethod.Build(); err == nil {
		t.Fatal("unsupported domain method must be rejected at build time")
	}

	ok := &Xdns{
		Domains:   []string{"t.example", "a.example:a"},
		Resolvers: []string{"q.example+udp://8.8.8.8:53"},
	}
	if _, err := ok.Build(); err != nil {
		t.Fatalf("valid mixed config rejected: %v", err)
	}
}
