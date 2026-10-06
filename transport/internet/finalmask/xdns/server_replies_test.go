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

func testQuery(name string, qtype dnsmessage.Type) dnsmessage.Message {
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}},
	}
}

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

// An authoritative server answers every query. A burst of queries for names
// outside the tunnel domain must get every NXDOMAIN, not a few: silently
// dropped replies leave resolvers timing out and set the server apart.
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
