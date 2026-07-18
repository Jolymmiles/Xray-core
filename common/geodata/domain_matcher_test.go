package geodata

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common/geodata/strmatcher"
	"github.com/xtls/xray-core/common/utils"
)

func TestParseDomainOptimizesCanonicalSuffixRegex(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{`(^|\.)wa\.me$`, "wa.me"},
		{`(^|\.)whatsapp-plus\.info$`, "whatsapp-plus.info"},
		{`(^|\.)Example\.COM$`, "Example.COM"},
	}
	for _, test := range tests {
		matcher, err := parseDomain(&Domain{Type: Domain_Regex, Value: test.pattern})
		if err != nil {
			t.Fatalf("parseDomain(%q) failed: %v", test.pattern, err)
		}
		domainMatcher, ok := matcher.(strmatcher.DomainMatcher)
		if !ok {
			t.Fatalf("parseDomain(%q) returned %T, want strmatcher.DomainMatcher", test.pattern, matcher)
		}
		if got := domainMatcher.Pattern(); got != test.want {
			t.Fatalf("parseDomain(%q) pattern = %q, want %q", test.pattern, got, test.want)
		}
	}
}

func TestParseDomainKeepsGeneralRegex(t *testing.T) {
	patterns := []string{
		`(?i)(^|\.)example\.com$`,
		`^example\.com$`,
		`(^|\.)example[.]com$`,
		`(^|\.)example\.com.*$`,
	}
	for _, pattern := range patterns {
		matcher, err := parseDomain(&Domain{Type: Domain_Regex, Value: pattern})
		if err != nil {
			t.Fatalf("parseDomain(%q) failed: %v", pattern, err)
		}
		if _, ok := matcher.(*strmatcher.RegexMatcher); !ok {
			t.Fatalf("parseDomain(%q) returned %T, want *strmatcher.RegexMatcher", pattern, matcher)
		}
	}
}

func TestOptimizedSuffixRegexBehavior(t *testing.T) {
	matcher, err := parseDomain(&Domain{Type: Domain_Regex, Value: `(^|\.)whatsapp\.com$`})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		domain string
		want   bool
	}{
		{"whatsapp.com", true},
		{"web.whatsapp.com", true},
		{"notwhatsapp.com", false},
		{"whatsapp.com.example", false},
		{"WHATSAPP.COM", false},
	}
	for _, test := range tests {
		if got := matcher.Match(test.domain); got != test.want {
			t.Errorf("Match(%q) = %v, want %v", test.domain, got, test.want)
		}
	}
}

func TestCompactDomainMatcher_PreservesCustomRuleIndices(t *testing.T) {
	factory := &CompactDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.LinearAnyMatcher]()}
	matcher, err := factory.BuildMatcher([]*DomainRule{
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Full, Value: "example.com"}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Domain, Value: "example.com"}}},
	})
	if err != nil {
		t.Fatalf("BuildMatcher() failed: %v", err)
	}

	got := matcher.Match("example.com")
	slices.Sort(got)

	want := []uint32{0, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Match() = %v, want %v", got, want)
	}
}

func TestCompactDomainMatcher_PreservesMixedRuleIndices(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	factory := &CompactDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.LinearAnyMatcher]()}
	matcher, err := factory.BuildMatcher([]*DomainRule{
		{Value: &DomainRule_Geosite{Geosite: &GeoSiteRule{File: DefaultGeoSiteDat, Code: "CN"}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Full, Value: "163.com"}}},
	})
	if err != nil {
		t.Fatalf("BuildMatcher() failed: %v", err)
	}

	got := matcher.Match("163.com")
	slices.Sort(got)

	want := []uint32{0, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Match() = %v, want %v", got, want)
	}
}

func TestMphDomainMatcher_MatchReturnsDetachedSlice(t *testing.T) {
	matcher, err := (&MphDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.MphValueMatcher]()}).
		BuildMatcher([]*DomainRule{
			{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Full, Value: "example.com"}}},
			{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Domain, Value: "example.com"}}},
		})
	if err != nil {
		t.Fatalf("BuildMatcher() failed: %v", err)
	}

	got := matcher.Match("example.com")
	if !reflect.DeepEqual(got, []uint32{0, 1}) {
		t.Fatalf("Match() = %v, want %v", got, []uint32{0, 1})
	}

	got[0] = 1

	gotAgain := matcher.Match("example.com")
	if !reflect.DeepEqual(gotAgain, []uint32{0, 1}) {
		t.Fatalf("Match() after caller mutation = %v, want %v", gotAgain, []uint32{0, 1})
	}
}
