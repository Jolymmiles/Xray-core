package xdns

import (
	"errors"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/dns/dnsmessage"
)

// The server tests below come from the xdns hardening on TaiLerV's
// sync/upstream-2026-10-02 branch, adapted to this tree.

// testServerConfig configures a server for the tunnel domain t.example.com
// that answers TXT queries.
func testServerConfig() *Config {
	return &Config{Domains: []*DomainProto{{Name: "t.example.com", LenLimit: 255, LabelLimit: 63, Types: []int32{int32(TypeTXT)}}}}
}

// startTestServer runs an xdns server on a loopback socket and returns the
// address queries reach it on.
func startTestServer(t *testing.T) net.Addr {
	t.Helper()
	raw, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testServerConfig(), raw)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return raw.LocalAddr()
}

// exchange sends one query to the server and returns the parsed reply.
func exchange(t *testing.T, server net.Addr, query dnsmessage.Message) (dnsmessage.Message, error) {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo(packed, server); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var reply dnsmessage.Message
	return reply, reply.Unpack(buf[:n])
}

// testQuery returns a recursive query for name and qtype.
func testQuery(name string, qtype dnsmessage.Type) dnsmessage.Message {
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}},
	}
}

// optRecord returns an OPT record for EDNS version with a 1232-byte UDP
// payload size.
func optRecord(version uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232, TTL: version << 16},
		Body:   &dnsmessage.OPTResource{},
	}
}

// Error replies must be marked as responses like any DNS server's: an
// unsupported EDNS version gets BADVERS and a second OPT record FORMERR. A
// reply that still looks like a query sets the server apart from every DNS
// server a prober compares it with.
func TestServerErrorRepliesAreResponses(t *testing.T) {
	server := startTestServer(t)

	badVersion := testQuery("probe.t.example.com.", dnsmessage.TypeTXT)
	badVersion.Additionals = []dnsmessage.Resource{optRecord(1)}
	reply, err := exchange(t, server, badVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Header.Response || len(reply.Additionals) != 1 || reply.Additionals[0].Header.TTL>>24 != 1 {
		t.Fatalf("EDNS version 1 reply = %+v %+v, want a BADVERS response", reply.Header, reply.Additionals)
	}

	twoOPT := testQuery("probe.t.example.com.", dnsmessage.TypeTXT)
	twoOPT.Additionals = []dnsmessage.Resource{optRecord(0), optRecord(0)}
	reply, err = exchange(t, server, twoOPT)
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Header.Response || reply.Header.RCode != dnsmessage.RCodeFormatError {
		t.Fatalf("duplicate OPT reply = %+v, want a FORMERR response", reply.Header)
	}
}

// amplifyingQuery packs a query by hand: a 253-character question name and
// srv additional SRV records whose owner and target names point back at it.
// dnsmessage expands those pointers when it unpacks the query but packs SRV
// targets without compression, so a reply echoing the records grows several
// times larger than the query.
func amplifyingQuery(opcode byte, srv int) []byte {
	query := []byte{0x42, 0x42, opcode << 3, 0, 0, 1, 0, 0, 0, 0, byte(srv >> 8), byte(srv)}
	for _, length := range []int{63, 63, 63, 60} {
		query = append(query, byte(length))
		for i := range length {
			query = append(query, 'a'+byte(i%26))
		}
	}
	query = append(query, 0, 0, byte(dnsmessage.TypeTXT), 0, 1)
	for range srv {
		query = append(query, 0xC0, 12, 0, byte(dnsmessage.TypeSRV), 0, 1, 0, 0, 0, 60, 0, 8)
		query = append(query, 0, 0, 0, 0, 0, 80, 0xC0, 12)
	}
	return query
}

// exchangeRaw sends query to the server as is and returns the reply with its
// length on the wire.
func exchangeRaw(t *testing.T, server net.Addr, query []byte) (dnsmessage.Message, int) {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo(query, server); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no reply to a %d-byte query: %v", len(query), err)
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	return reply, n
}

// A query from an unauthenticated, possibly spoofed address must not draw a
// reply larger than itself: echoing the query's records turned one 510-byte
// query into a 3.5 KB reply. An error reply carries only the header and the
// question.
func TestServerErrorRepliesDoNotOutgrowQueries(t *testing.T) {
	server := startTestServer(t)
	for _, tc := range []struct {
		name   string
		opcode byte
		rcode  dnsmessage.RCode
	}{
		{"unsupported opcode", 1, dnsmessage.RCodeNotImplemented},
		{"name outside the domain", 0, dnsmessage.RCodeNameError},
	} {
		query := amplifyingQuery(tc.opcode, 12)
		reply, n := exchangeRaw(t, server, query)
		if n > len(query) {
			t.Errorf("%s: %d-byte query drew a %d-byte reply", tc.name, len(query), n)
		}
		if reply.Header.RCode != tc.rcode || len(reply.Questions) != 1 || len(reply.Answers)+len(reply.Authorities)+len(reply.Additionals) != 0 {
			t.Errorf("%s: reply %+v with %d answers, %d authorities, %d additionals, want only %v and the question",
				tc.name, reply.Header, len(reply.Answers), len(reply.Authorities), len(reply.Additionals), tc.rcode)
		}
	}
}

// compressedQuestionQueries returns out-of-zone TXT queries packed by hand
// whose only question name is compressed against bytes that hold no earlier
// name, which RFC 1035, Section 4.1.4 does not allow: one points back into a
// label of the name itself, the others into the header. dnsmessage follows
// those pointers, so the question unpacks to a name longer than its bytes in
// the query. Resolvers do not send such queries; a prober can.
func compressedQuestionQueries() map[string][]byte {
	header := func(additionals byte) []byte {
		return []byte{0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, additionals}
	}
	question := func(query []byte, name ...byte) []byte {
		return append(append(query, name...), 0, byte(dnsmessage.TypeTXT), 0, 1)
	}
	opt := func(query []byte, version byte) []byte {
		return append(query, 0, 0, byte(dnsmessage.TypeOPT), 0x04, 0xD0, 0, version, 0, 0, 0, 0)
	}
	// From offset 13 the name reads as the label "x" and the root.
	intoOwnLabel := question(header(0), 4, 1, 'x', 0, 'y', 0xC0, 13)
	// From offset 5, QDCOUNT's low byte, the header reads as a one-byte label
	// and the root.
	intoHeader := question(header(0), 0xC0, 5)
	return map[string][]byte{
		"pointer into its own label":                           intoOwnLabel,
		"pointer into the header":                              intoHeader,
		"pointer into the header with EDNS":                    opt(question(header(1), 0xC0, 5), 0),
		"pointer into the header with an unknown EDNS version": opt(question(header(1), 0xC0, 5), 1),
	}
}

// A query that parses gets an answer, even when its question uses malformed
// compression and the reply carrying the expanded question would outgrow the
// query. The size limit stays: the answer is a FORMERR without the question,
// with the server's OPT record when the query has one, its extended RCODE
// bits cleared.
func TestServerAnswersMalformedCompressionWithFormatError(t *testing.T) {
	server := startTestServer(t)
	for name, query := range compressedQuestionQueries() {
		reply, n := exchangeRaw(t, server, query)
		if n > len(query) {
			t.Errorf("%s: %d-byte query drew a %d-byte reply", name, len(query), n)
		}
		header := reply.Header
		if !header.Response || header.ID != 0x4242 || header.RCode != dnsmessage.RCodeFormatError || header.Authoritative || !header.RecursionDesired {
			t.Errorf("%s: reply header %+v, want a non-authoritative FORMERR response to query 0x4242 with RD", name, header)
		}
		if len(reply.Questions)+len(reply.Answers)+len(reply.Authorities) != 0 {
			t.Errorf("%s: reply carries %d questions, %d answers and %d authorities, want none", name, len(reply.Questions), len(reply.Answers), len(reply.Authorities))
		}
		hasOPT := len(query) > 12 && query[11] == 1
		switch {
		case !hasOPT && len(reply.Additionals) != 0:
			t.Errorf("%s: reply additionals %+v, want none", name, reply.Additionals)
		case hasOPT && (len(reply.Additionals) != 1 || reply.Additionals[0].Header.Type != dnsmessage.TypeOPT):
			t.Errorf("%s: reply additionals %+v, want only an OPT record", name, reply.Additionals)
		case hasOPT && (reply.Additionals[0].Header.Class != 1232 || reply.Additionals[0].Header.TTL>>16 != 0):
			t.Errorf("%s: reply OPT %+v, want size 1232, extended RCODE 0 and version 0", name, reply.Additionals[0].Header)
		}
	}
}

// An error reply carries the server's own OPT record, not the one the query
// sent: the query's EDNS options, extended RCODE and other records stay out,
// and header bits a query has no business setting are not reflected. DO is
// copied from a version 0 OPT record only, the one version whose flags the
// server knows.
func TestServerErrorRepliesCarryOwnOPTRecord(t *testing.T) {
	server := startTestServer(t)
	for _, tc := range []struct {
		name    string
		qname   string
		version uint32
		extRC   uint32
		do      bool
	}{
		{"unsupported EDNS version", "probe.t.example.com.", 1, 1, false},
		{"name outside the domain", "probe.example.org.", 0, 0, true},
	} {
		query := testQuery(tc.qname, dnsmessage.TypeTXT)
		query.Header.Truncated = true
		query.Header.RecursionAvailable = true
		query.Header.AuthenticData = true
		opt := optRecord(tc.version)
		opt.Header.TTL |= 0x7F<<24 | 1<<15
		opt.Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 3, Data: make([]byte, 64)}}}
		query.Additionals = []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("probe.example.org."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{"echo"}}},
			opt,
		}
		reply, err := exchange(t, server, query)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Header.Truncated || reply.Header.RecursionAvailable || reply.Header.AuthenticData || !reply.Header.RecursionDesired {
			t.Errorf("%s: reply header %+v reflects the query's flags", tc.name, reply.Header)
		}
		if len(reply.Additionals) != 1 || reply.Additionals[0].Header.Type != dnsmessage.TypeOPT {
			t.Fatalf("%s: reply additionals %+v, want only an OPT record", tc.name, reply.Additionals)
		}
		got := reply.Additionals[0]
		if got.Header.Class != 1232 || got.Header.TTL>>24 != tc.extRC || got.Header.TTL&0xFF0000 != 0 || got.Header.DNSSECAllowed() != tc.do || len(got.Body.(*dnsmessage.OPTResource).Options) != 0 {
			t.Errorf("%s: reply OPT %+v %+v, want size 1232, extended RCODE %d, version 0, DO %v and no options", tc.name, got.Header, got.Body, tc.extRC, tc.do)
		}
	}
}

// The server is the delegated nameserver of its domain, so the zone apex
// exists: it must get an authoritative answer without data, like any name in
// the zone, not the NXDOMAIN of a name outside it. NXDOMAIN at the apex would
// deny the whole zone below it (RFC 8020) and tells one probe apart from an
// authoritative server.
func TestServerAnswersZoneApexAuthoritatively(t *testing.T) {
	server := startTestServer(t)
	for _, query := range []dnsmessage.Message{
		testQuery("t.example.com.", dnsmessage.TypeSOA),
		testQuery("t.example.com.", dnsmessage.TypeNS),
		testQuery("T.Example.COM.", dnsmessage.TypeTXT),
		testQuery("t.example.com.", dnsmessage.TypeA),
		testQuery("probe.t.example.com.", dnsmessage.TypeMX),
	} {
		reply, err := exchange(t, server, query)
		if err != nil {
			t.Fatal(err)
		}
		q := query.Questions[0]
		if reply.Header.RCode != dnsmessage.RCodeSuccess || !reply.Header.Authoritative || len(reply.Answers) != 0 {
			t.Errorf("%s %v: reply %+v with %d answers, want an authoritative NOERROR without data", q.Name, q.Type, reply.Header, len(reply.Answers))
		}
	}
}

// An authoritative server answers every query. A burst of queries for names
// outside the tunnel domain that fits the 128-slot reply queue must get every
// NXDOMAIN, not a few: silently dropped replies leave resolvers timing out and
// set the server apart. A burst beyond the queue still loses replies.
func TestServerAnswersBurstOfRejectedQueries(t *testing.T) {
	server := startTestServer(t)
	conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const burst = 32
	for i := range burst {
		query := testQuery("probe.example.org.", dnsmessage.TypeTXT)
		query.Header.ID = uint16(i)
		packed, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.WriteTo(packed, server); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[uint16]bool)
	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for len(seen) < burst {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("answered %d of %d rejected queries: %v", len(seen), burst, err)
		}
		var reply dnsmessage.Message
		if err := reply.Unpack(buf[:n]); err != nil || reply.Header.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("unexpected reply %+v (%v)", reply.Header, err)
		}
		seen[reply.Header.ID] = true
	}
}

// flakyPacketConn fails a number of reads before delegating, like a socket
// or inner mask reporting a transient error.
type flakyPacketConn struct {
	net.PacketConn
	failures atomic.Int32
}

// ReadFrom fails until the configured number of failures is used up, then
// reads from the wrapped connection.
func (c *flakyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.failures.Add(-1) >= 0 {
		return 0, nil, errors.New("transient read failure")
	}
	return c.PacketConn.ReadFrom(p)
}

// A read error that is not caused by Close must not stop the server from
// answering later queries.
func TestServerKeepsReadingAfterTransientError(t *testing.T) {
	raw, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	flaky := &flakyPacketConn{PacketConn: raw}
	flaky.failures.Store(2)
	server, err := NewServer(testServerConfig(), flaky)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	defer server.Close()

	reply, err := exchange(t, raw.LocalAddr(), testQuery("probe.example.org.", dnsmessage.TypeTXT))
	if err != nil {
		t.Fatalf("no answer after transient read errors: %v", err)
	}
	if reply.Header.ID != 0x4242 || reply.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("reply = %+v, want NXDOMAIN for query 0x4242", reply.Header)
	}
}
