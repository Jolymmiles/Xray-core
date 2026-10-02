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

func testClientID(i int) ClientID {
	return ClientIDFromRaw([8]byte{0, 0, 0, 0, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

// Per-client send queues are created from client-chosen IDs before any
// authentication, so the table must stay bounded while known clients keep
// their queues.
func TestSendManagerBoundsClientQueues(t *testing.T) {
	m := NewSendManager()
	defer m.Close()

	for i := range sendClientCount {
		if _, _, ok := m.Pop(testClientID(i)); !ok {
			t.Fatalf("client %d refused below the limit", i)
		}
	}
	if _, _, ok := m.Pop(testClientID(sendClientCount)); ok {
		t.Fatal("a client beyond the limit got a queue")
	}
	m.Push(testClientID(sendClientCount+1), []byte("over limit"))
	m.mu.Lock()
	tracked := len(m.m)
	m.mu.Unlock()
	if tracked != sendClientCount {
		t.Fatalf("tracked clients = %d, want %d", tracked, sendClientCount)
	}

	known := testClientID(7)
	m.Push(known, []byte("data"))
	ch, _, ok := m.Pop(known)
	if !ok {
		t.Fatal("a known client lost its queue at the limit")
	}
	if got := <-ch; string(got) != "data" {
		t.Fatalf("queued %q, want data", got)
	}
}

// Fragment accounting must not keep a size entry for every client ID it has
// ever seen once that client's fragments are gone.
func TestFragManagerReleasesClientAccounting(t *testing.T) {
	m := NewFragManager()
	defer m.Close()

	out := make([]byte, fragSize)
	for i := range 64 {
		key := FragKey{clientID: testClientID(i), fragID: 1}
		if n := m.Feed(out, key, 0, 2, []byte("first-")); n != 0 {
			t.Fatalf("first fragment completed a message: %d", n)
		}
		if n := m.Feed(out, key, 1, 2, []byte("second")); n != len("first-second") {
			t.Fatalf("reassembled %d bytes, want %d", n, len("first-second"))
		}
	}
	m.mu.Lock()
	entries, accounted := len(m.m), len(m.sizem)
	m.mu.Unlock()
	if entries != 0 || accounted != 0 {
		t.Fatalf("after reassembly: %d entries, %d client size records; want none", entries, accounted)
	}
}
