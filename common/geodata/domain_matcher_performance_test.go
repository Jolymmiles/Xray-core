package geodata

import "testing"

var remnaDomainExcludeRules = []string{
	"courier.push.apple.com",
	"dlg.io.mi.com",
	"push.apple.com",
	"api.push.apple.com",
	`regexp:(^|\.)wa\.me$`,
	`regexp:(^|\.)whatsapp-plus\.info$`,
	`regexp:(^|\.)whatsapp-plus\.me$`,
	`regexp:(^|\.)whatsapp-plus\.net$`,
	`regexp:(^|\.)whatsapp\.cc$`,
	`regexp:(^|\.)whatsapp\.com$`,
	`regexp:(^|\.)whatsapp\.info$`,
	`regexp:(^|\.)whatsapp\.net$`,
	`regexp:(^|\.)whatsapp\.orgs$`,
	`regexp:(^|\.)whatsapp\.tv$`,
	`regexp:(^|\.)whatsappbrand\.com$`,
}

var domainMatchAnySink bool

func benchmarkRemnaDomainExclude(b *testing.B, domain string) {
	rules, err := ParseDomainRules(remnaDomainExcludeRules, Domain_Domain)
	if err != nil {
		b.Fatal(err)
	}
	matcher, err := newDomainMatcherFactory().BuildMatcher(rules)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		domainMatchAnySink = matcher.MatchAny(domain)
	}
}

func BenchmarkRemnaDomainExcludeMiss(b *testing.B) {
	benchmarkRemnaDomainExclude(b, "example.com")
}

func BenchmarkRemnaDomainExcludeExactHit(b *testing.B) {
	benchmarkRemnaDomainExclude(b, "courier.push.apple.com")
}

func BenchmarkRemnaDomainExcludeRegexpHit(b *testing.B) {
	benchmarkRemnaDomainExclude(b, "web.whatsapp.com")
}
