package header

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// The peer strips the header by its length and never parses it, so a name
// that is accepted must pack the same bytes as upstream Xray and earlier
// versions of this fork do. Each one packs a query with one A/IN question
// for exactly that name, which is what a DNS parser on the path sees.
func TestHeaderDNSPacksAWellFormedQuestionAsBefore(t *testing.T) {
	longest := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61) // 255 bytes on the wire
	for _, c := range []struct {
		domain   string
		question string // hex after the 12-byte header; empty to skip the byte comparison
	}{
		{"www.baidu.com", "0377777705626169647503636f6d0000010001"},
		{"t.example", "0174076578616d706c650000010001"},
		{"T.Example", "0154074578616d706c650000010001"},
		{"xn--bcher-kva.example", "0d786e2d2d62636865722d6b7661076578616d706c650000010001"},
		{"_srv.t.example", "045f7372760174076578616d706c650000010001"},
		{longest, ""},
	} {
		h, err := NewHeaderDNS(c.domain)
		if err != nil {
			t.Errorf("NewHeaderDNS(%q): %v", c.domain, err)
			continue
		}
		b := make([]byte, h.Size())
		h.Serialize(b)
		if got, want := hex.EncodeToString(b[2:12]), "01000001000000000000"; got != want {
			t.Errorf("NewHeaderDNS(%q) header = %s, want %s", c.domain, got, want)
		}
		if c.question != "" {
			if got := hex.EncodeToString(b[12:]); got != c.question {
				t.Errorf("NewHeaderDNS(%q) question = %s, want %s", c.domain, got, c.question)
			}
		}
		if got, want := h.Size(), 12+len(c.domain)+2+4; got != want {
			t.Errorf("NewHeaderDNS(%q) size = %d, want %d", c.domain, got, want)
		}

		var p dnsmessage.Parser
		header, err := p.Start(b)
		if err != nil {
			t.Errorf("NewHeaderDNS(%q) header does not parse: %v", c.domain, err)
			continue
		}
		q, err := p.Question()
		if err != nil {
			t.Errorf("NewHeaderDNS(%q) question does not parse: %v", c.domain, err)
			continue
		}
		if header.Response || q.Name.String() != c.domain+"." || q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
			t.Errorf("NewHeaderDNS(%q) = response %v, question %v, want a query for %s A IN", c.domain, header.Response, q, c.domain+".")
		}
	}
}

// A name that would not pack into a well-formed question for itself fails
// with an error that names the domain. It is not rewritten: a rewritten name
// changes the header length, so a peer that still packs the configured
// spelling, such as upstream Xray, would silently stop understanding it.
func TestHeaderDNSRejectsNamesThatPackAMalformedQuestion(t *testing.T) {
	label64 := strings.Repeat("a", 64)
	tooLong := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 62) // 256 bytes on the wire
	for _, c := range []struct{ domain, reason string }{
		{"", "empty label"},
		{".", "empty label"},
		{".t.example", "empty label"},
		{"t..example", "empty label"},
		{"t.example..", "empty label"},
		{"t.example.", `trailing dot; write "t.example"`},
		{"bücher.example", `non-ASCII name; write its punycode form "xn--bcher-kva.example"`},
		{"Bücher.example.", `non-ASCII name; write its punycode form "xn--bcher-kva.example"`},
		{"bü_cher.example", `non-ASCII name; write its punycode form "xn--b_cher-3ya.example"`},
		{"bücher..example", `non-ASCII name whose punycode form "xn--bcher-kva..example" is invalid: empty label`},
		{"\xff.example", `non-ASCII name with no punycode form: idna: invalid label "\xff"`},
		{`t.example\`, "backslash escapes are not supported"},
		{`t\.example`, "backslash escapes are not supported"},
		{label64 + ".example", `label "` + label64 + `" is longer than 63 bytes`},
		{tooLong, "name of 256 bytes on the wire is longer than 255 bytes"},
		{tooLong + "a", "name of 257 bytes on the wire is longer than 255 bytes"},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("NewHeaderDNS(%q) panicked: %v", c.domain, r)
				}
			}()
			h, err := NewHeaderDNS(c.domain)
			if err == nil {
				b := make([]byte, h.Size())
				h.Serialize(b)
				t.Errorf("NewHeaderDNS(%q) accepted, packs question %s", c.domain, hex.EncodeToString(b[12:]))
				return
			}
			if want := "invalid domain " + strconv.Quote(c.domain) + ": " + c.reason; err.Error() != want {
				t.Errorf("NewHeaderDNS(%q) error = %q, want %q", c.domain, err, want)
			}
		}()
	}
}
