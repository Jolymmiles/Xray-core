package xdns

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// testDomain returns the tunnel domain t.example.com with the given query
// types.
func testDomain(t *testing.T, types ...uint16) *Domain {
	t.Helper()
	domain, err := NewDomain("t.example.com", 255, 63, types, 0)
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

// A name belongs to the tunnel domain only below it, at a label boundary.
// Sibling names that share a suffix, like foot.example.com for
// t.example.com, must get the answers of a DNS server for t.example.com,
// not tunnel answers. From TaiLerV's sync/upstream-2026-10-02 branch.
func TestDomainMatchesWholeLabels(t *testing.T) {
	domain := testDomain(t, TypeTXT)
	for name, want := range map[string]bool{
		"aaaa.t.example.com.": true,
		"AAAA.T.EXAMPLE.COM.": true,
		"a.b.t.example.com.":  true,
		"t.example.com.":      false,
		"foot.example.com.":   false,
		"xt.example.com.":     false,
		"aaaa.t.example.org.": false,
	} {
		if got := domain.IsDomain(dnsmessage.MustNewName(name)); got != want {
			t.Errorf("IsDomain(%q) = %v, want %v", name, got, want)
		}
	}
}

// The apex is the domain itself, in any letter case; names below or beside it
// are not.
func TestDomainRecognizesItsApex(t *testing.T) {
	domain := testDomain(t, TypeTXT)
	for name, want := range map[string]bool{
		"t.example.com.":      true,
		"T.EXAMPLE.COM.":      true,
		"aaaa.t.example.com.": false,
		"xt.example.com.":     false,
		"example.com.":        false,
		"t.example.org.":      false,
	} {
		if got := domain.IsApex(dnsmessage.MustNewName(name)); got != want {
			t.Errorf("IsApex(%q) = %v, want %v", name, got, want)
		}
	}
}
