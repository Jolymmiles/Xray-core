package xdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
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

// DNS over TCP frames every message with a two-byte length (RFC 1035
// section 4.2.2); the resolver must send that prefix before each query.
func TestTCPResolverFramesQueries(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type frame struct {
		length int
		body   []byte
		err    error
	}
	received := make(chan frame, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- frame{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			received <- frame{err: err}
			return
		}
		length := int(binary.BigEndian.Uint16(prefix[:]))
		body := make([]byte, length)
		_, err = io.ReadFull(conn, body)
		received <- frame{length: length, body: body, err: err}
	}()

	resolver, err := NewTCPResolver(&TCPResolverProto{Addr: listener.Addr().String()}, testDialer())
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	message := testQuery("probe.t.example.com.", dnsmessage.TypeTXT)
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	resolver.Send(query)

	got := <-received
	if got.err != nil {
		t.Fatalf("reading the framed query: %v (length prefix %d)", got.err, got.length)
	}
	if got.length != len(query) || !bytes.Equal(got.body, query) {
		t.Fatalf("framed query = %d bytes %x, want %d bytes %x", got.length, got.body, len(query), query)
	}
}

type trackedPacketConn struct {
	net.PacketConn
	once   sync.Once
	closed *atomic.Int32
}

// Close counts each socket once, however many owners close it.
func (c *trackedPacketConn) Close() error {
	c.once.Do(func() { c.closed.Add(1) })
	return c.PacketConn.Close()
}

// The client reaches its resolvers through the finalmask dialer, so the
// finalmask must not pre-dial a socket for it that nothing owns.
func TestClientOwnsEveryDialedSocket(t *testing.T) {
	resolverPeer, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer resolverPeer.Close()

	var opened, closed atomic.Int32
	dialUDP := func(ctx context.Context, dest net.Destination) (net.PacketConn, net.Addr, error) {
		conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		opened.Add(1)
		return &trackedPacketConn{PacketConn: conn, closed: &closed}, &net.UDPAddr{IP: dest.Address.IP(), Port: int(dest.Port)}, nil
	}
	config := testServerConfig()
	config.Resolvers = []*serial.TypedMessage{serial.ToTypedMessage(&UDPResolverProto{Addr: resolverPeer.LocalAddr().String()})}
	mask := finalmask.NewFinalMask(nil, []finalmask.UDPMask{config}, nil, nil, dialUDP, nil)

	conn, err := mask.DialUDP(context.Background(), net.UDPDestination(net.LocalHostIP, 443))
	if err != nil {
		t.Fatal(err)
	}
	closeWithin(t, "XDNS client", func() { _ = conn.Close() })
	if opened.Load() != closed.Load() {
		t.Fatalf("dialed %d sockets but closed %d", opened.Load(), closed.Load())
	}
}

// A name belongs to the tunnel domain only when the domain ends at a label
// boundary; a sibling such as foot.example.com is not under t.example.com.
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

func optRecord(version uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232, TTL: version << 16},
		Body:   &dnsmessage.OPTResource{},
	}
}

// Error replies must be marked as responses like any DNS server's: an
// unsupported EDNS version gets BADVERS and a second OPT record FORMERR.
func TestServerErrorRepliesAreResponses(t *testing.T) {
	raw, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testServerConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	badVersion := testQuery("probe.t.example.com.", dnsmessage.TypeTXT)
	badVersion.Additionals = []dnsmessage.Resource{optRecord(1)}
	reply, err := exchange(t, raw.LocalAddr(), badVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Header.Response || len(reply.Additionals) != 1 || reply.Additionals[0].Header.TTL>>24 != 1 {
		t.Fatalf("EDNS version 1 reply = %+v %+v, want a BADVERS response", reply.Header, reply.Additionals)
	}

	twoOPT := testQuery("probe.t.example.com.", dnsmessage.TypeTXT)
	twoOPT.Additionals = []dnsmessage.Resource{optRecord(0), optRecord(0)}
	reply, err = exchange(t, raw.LocalAddr(), twoOPT)
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Header.Response || reply.Header.RCode != dnsmessage.RCodeFormatError {
		t.Fatalf("duplicate OPT reply = %+v, want a FORMERR response", reply.Header)
	}
}

// A client and server joined through a loopback resolver must carry data both
// ways while both sides read, write, and close concurrently.
func TestLoopbackExchangeAndClose(t *testing.T) {
	raw, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testServerConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := testServerConfig()
	clientConfig.Resolvers = []*serial.TypedMessage{serial.ToTypedMessage(&UDPResolverProto{Addr: raw.LocalAddr().String()})}
	client, err := NewClient(clientConfig, testDialer())
	if err != nil {
		t.Fatal(err)
	}

	const rounds = 5
	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for range rounds {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				serverDone <- err
				return
			}
			reply := append([]byte("pong:"), buf[:n]...)
			if _, err := server.WriteTo(reply, addr); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	buf := make([]byte, 4096)
	for i := range rounds {
		want := []byte{'p', 'i', 'n', 'g', byte('0' + i)}
		if _, err := client.WriteTo(want, &net.UDPAddr{IP: stdnet.IPv4zero}); err != nil {
			t.Fatal(err)
		}
		readDone := make(chan error, 1)
		go func() {
			n, _, err := client.ReadFrom(buf)
			if err == nil && !bytes.Equal(buf[:n], append([]byte("pong:"), want...)) {
				err = errors.New("unexpected reply " + string(buf[:n]))
			}
			readDone <- err
		}()
		select {
		case err := <-readDone:
			if err != nil {
				t.Fatalf("round %d: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: no reply through the loopback resolver", i)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	closeWithin(t, "XDNS client", func() { _ = client.Close() })
	closeWithin(t, "XDNS server", func() { _ = server.Close() })
}

// Error replies are queued for the writer goroutine; a burst of queries the
// server rejects must not lose replies while that goroutine is busy.
func TestServerAnswersBurstOfRejectedQueries(t *testing.T) {
	raw, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testServerConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

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
		if _, err := conn.WriteTo(packed, raw.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[uint16]bool)
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
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
