package xdns

import (
	"bytes"
	"errors"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
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

func testServerConfig() *Config {
	return &Config{Domains: []*DomainProto{{Name: "t.example.com", LenLimit: 255, LabelLimit: 63, Types: []int32{int32(TypeTXT)}}}}
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

// testDialer reaches resolvers over plain loopback sockets, like the
// finalmask dialer without masks.
func testDialer() *finalmask.Dialer {
	return &finalmask.Dialer{
		DialTCP: func(dest net.Destination) (net.Conn, error) {
			return stdnet.Dial("tcp", dest.NetAddr())
		},
		DialUDP: func(dest net.Destination) (net.Conn, error) {
			conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			return &net.PacketConnWrapper{PacketConn: conn, Dest: &net.UDPAddr{IP: dest.Address.IP(), Port: int(dest.Port)}}, nil
		},
	}
}

func closeWithin(t *testing.T, name string, closeFn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		closeFn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s Close did not return", name)
	}
}

// Close must not wait for the receive goroutine while holding the lock that
// goroutine needs to finish.
func TestResolverCloseReturns(t *testing.T) {
	udpPeer, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpPeer.Close()
	tcpPeer, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpPeer.Close()
	accepted := make(chan stdnet.Conn, 1)
	go func() {
		if conn, err := tcpPeer.Accept(); err == nil {
			accepted <- conn
		}
	}()

	udp, err := NewUDPResolver(&UDPResolverProto{Addr: udpPeer.LocalAddr().String()}, testDialer())
	if err != nil {
		t.Fatal(err)
	}
	closeWithin(t, "UDP resolver", udp.Close)

	tcp, err := NewTCPResolver(&TCPResolverProto{Addr: tcpPeer.Addr().String()}, testDialer())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		select {
		case conn := <-accepted:
			conn.Close()
		default:
		}
	}()
	closeWithin(t, "TCP resolver", tcp.Close)
}
