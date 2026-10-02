package xdns

import (
	"bytes"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func testDomain(t *testing.T, types ...uint16) *Domain {
	t.Helper()
	domain, err := NewDomain("t.example.com", 255, 63, types, 0)
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

func testResponse(t *testing.T, qtype dnsmessage.Type, answers ...dnsmessage.Resource) dnsmessage.Message {
	t.Helper()
	name := dnsmessage.MustNewName("aaaa.t.example.com.")
	for i := range answers {
		answers[i].Header.Name = name
		answers[i].Header.Type = qtype
		answers[i].Header.Class = dnsmessage.ClassINET
	}
	return dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
		Answers:   answers,
	}
}

// Decode writes into the caller's buffer and its result is used to reslice
// that buffer, so it must never report more bytes than the buffer holds.
func TestRespDecodeStaysWithinBuffer(t *testing.T) {
	txt := testResponse(t, dnsmessage.TypeTXT, dnsmessage.Resource{
		Body: &dnsmessage.TXTResource{TXT: []string{string(bytes.Repeat([]byte{'x'}, 64))}},
	})
	var answers []dnsmessage.Resource
	for i := range 8 {
		answers = append(answers, dnsmessage.Resource{Body: &dnsmessage.AResource{A: [4]byte{byte(i), 8, 1, 2}}})
	}
	a := testResponse(t, dnsmessage.TypeA, answers...)

	for name, msg := range map[string]dnsmessage.Message{"TXT": txt, "A": a} {
		t.Run(name, func(t *testing.T) {
			resp := NewResp(msg, testDomain(t, uint16(msg.Questions[0].Type)), 0)
			full := make([]byte, 4096)
			if n := resp.Decode(full); n <= 8 {
				t.Fatalf("Decode into a large buffer = %d, want the whole payload", n)
			}
			short := make([]byte, 8, 8)
			if n := resp.Decode(short); n > len(short) {
				t.Fatalf("Decode reported %d bytes for an %d-byte buffer", n, len(short))
			}
		})
	}
}
