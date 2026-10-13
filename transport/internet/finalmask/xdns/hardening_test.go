package xdns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/dns/dnsmessage"
)

const hardeningDomain = "t.example"

// blockingPacketConn is a server socket that never receives anything, so the
// server goroutines idle while a test feeds queries through read directly.
type blockingPacketConn struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newBlockingPacketConn() *blockingPacketConn {
	return &blockingPacketConn{closed: make(chan struct{})}
}

func (c *blockingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, io.EOF
}

func (c *blockingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

func (c *blockingPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *blockingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func hardeningConfig() *Config {
	return &Config{Domains: []*DomainProto{{Name: hardeningDomain, LenLimit: 255, LabelLimit: 63}}}
}

func hardeningTestDomain(t *testing.T) *Domain {
	t.Helper()
	domain, err := NewDomain(hardeningDomain, 255, 63, []uint16{TypeTXT}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

// packTXTQuery packs a TXT query whose name carries the given XDNS payload.
func packTXTQuery(t *testing.T, domain *Domain, payload []byte) []byte {
	t.Helper()
	msg := dnsmessage.Message{Questions: []dnsmessage.Question{{
		Name:  domain.Encode(payload),
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
	}}}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

// A fragment header occupies bytes 12..14, so a fragmented query shorter than
// 16 bytes carries no complete header and payload. Such queries arrive before
// any authentication and must be dropped instead of crashing the server.
func TestServerDropsShortFragmentQuery(t *testing.T) {
	conn, err := NewServer(hardeningConfig(), newBlockingPacketConn())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := conn.(*xdnsServer)
	domain := hardeningTestDomain(t)
	for _, length := range []int{13, 14, 15} {
		payload := make([]byte, length)
		payload[0] = TypeMap[TypeTXT]
		payload[8] = 3 | 0xC0
		query := packTXTQuery(t, domain, payload)
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("%d-byte fragment query panicked: %v", length, recovered)
				}
			}()
			server.read(query, &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 53})
		}()
	}
}

// fragmentQuery packs one upload fragment as a client sends it: client ID,
// kind 3|0xC0, the packet's 3-byte nonce, fragment ID, index and count, data.
func fragmentQuery(t *testing.T, domain *Domain, clientID [8]byte, nonce [3]byte, fragID, index, count byte, data string) []byte {
	t.Helper()
	payload := make([]byte, 15+len(data))
	copy(payload, clientID[:])
	payload[0] |= TypeMap[TypeTXT]
	payload[8] = 3 | 0xC0
	copy(payload[9:12], nonce[:])
	payload[12], payload[13], payload[14] = fragID, index, count
	copy(payload[15:], data)
	return packTXTQuery(t, domain, payload)
}

// The fragment ID is one byte, so a busy client reuses it within the fragment
// TTL. When a fragment of the earlier packet was lost, the later packet's
// fragments must not complete the earlier packet's entry: the server would
// deliver a packet spliced from two, and a transport without its own
// integrity check (mKCP without a mask) passes the splice into the stream.
func TestServerKeepsFragmentsOfDifferentPacketsApart(t *testing.T) {
	conn, err := NewServer(hardeningConfig(), newBlockingPacketConn())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	server := conn.(*xdnsServer)
	domain := hardeningTestDomain(t)
	clientID := [8]byte{0x10, 1, 2, 3, 4, 5, 6, 7}
	from := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 53}

	queries := [][]byte{
		// Packet A loses its middle fragment.
		fragmentQuery(t, domain, clientID, [3]byte{0xA, 0xA, 0xA}, 7, 0, 3, "A0A0"),
		fragmentQuery(t, domain, clientID, [3]byte{0xA, 0xA, 0xA}, 7, 2, 3, "A2A2"),
		// Packet B reuses fragment ID 7 and arrives whole.
		fragmentQuery(t, domain, clientID, [3]byte{0xB, 0xB, 0xB}, 7, 0, 3, "B0B0"),
		fragmentQuery(t, domain, clientID, [3]byte{0xB, 0xB, 0xB}, 7, 1, 3, "B1B1"),
		fragmentQuery(t, domain, clientID, [3]byte{0xB, 0xB, 0xB}, 7, 2, 3, "B2B2"),
	}
	go func() {
		for _, query := range queries {
			server.read(query, from)
		}
	}()

	delivered := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		if n, _, err := conn.ReadFrom(buf); err == nil {
			delivered <- string(buf[:n])
		}
	}()
	select {
	case packet := <-delivered:
		if packet != "B0B0B1B1B2B2" {
			t.Fatalf("server delivered %q, want packet B %q", packet, "B0B0B1B1B2B2")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server delivered no packet; want packet B")
	}
}

// DNS over TCP prefixes every message with its length as a big-endian uint16
// (RFC 1035 section 4.2.2).
func TestTCPResolverFramesMessagesWithLength(t *testing.T) {
	client, server := stdnet.Pipe()
	defer server.Close()
	resolver := &TCPResolver{conn: client, closeCh: make(chan struct{})}
	defer client.Close()

	message := []byte("dns message")
	go resolver.Send(message)

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame := make([]byte, 2+len(message))
	if _, err := io.ReadFull(server, frame); err != nil {
		t.Fatalf("read framed message: %v", err)
	}
	if length := int(frame[0])<<8 | int(frame[1]); length != len(message) || string(frame[2:]) != string(message) {
		t.Fatalf("TCP frame = %q, want 2-byte length %d then %q", frame, len(message), message)
	}
}

// Completing a fragmented packet must not leave a per-client size counter
// behind: client IDs are chosen by unauthenticated peers.
func TestFragManagerForgetsClientsWithoutFragments(t *testing.T) {
	manager := NewFragManager()
	defer manager.Close()
	out := make([]byte, fragSize)
	for id := range 64 {
		key := FragKey{clientID: ClientID{byte(id), 1}, fragID: 1}
		manager.Feed(out, key, 0, 2, []byte("first"))
		if n := manager.Feed(out, key, 1, 2, []byte("second")); n != len("firstsecond") {
			t.Fatalf("client %d reassembled %d bytes", id, n)
		}
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.m) != 0 {
		t.Fatalf("after reassembly: %d fragment entries; want none", len(manager.m))
	}
}

// recordingResolver captures the queries a client sends.
type recordingResolver struct {
	sent      chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func newRecordingResolver() *recordingResolver {
	return &recordingResolver{sent: make(chan []byte, 64), closed: make(chan struct{})}
}

func (r *recordingResolver) Addr() *stdnet.UDPAddr {
	return &stdnet.UDPAddr{IP: stdnet.IP{192, 0, 2, 53}, Port: 53}
}

func (r *recordingResolver) Read([]byte) (int, error) {
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *recordingResolver) Send(p []byte) {
	r.sent <- append([]byte(nil), p...)
}

func (r *recordingResolver) Close() { r.closeOnce.Do(func() { close(r.closed) }) }

func newHardeningClient(t *testing.T, resolver Resolver) *xdnsClient {
	t.Helper()
	return &xdnsClient{
		clientID:      NewClientID(),
		domains:       []*Domain{hardeningTestDomain(t)},
		resolvers:     []Resolver{resolver},
		resolverSends: make([]atomic.Uint32, 1),
		readCh:        make(chan packet),
		poolCh:        make(chan struct{}, pollLimit),
		closeCh:       make(chan struct{}),
	}
}

// queryKind returns the XDNS kind byte of a query: 3 carries data, 8 polls.
func queryKind(t *testing.T, domain *Domain, query []byte) byte {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil {
		t.Fatal(err)
	}
	var decoded [255]byte
	if n := domain.Decode(&decoded, msg.Questions[0].Name); n < 9 {
		t.Fatalf("decoded query has %d bytes", n)
	}
	return decoded[8] & 0x3F
}

func nextQuery(t *testing.T, resolver *recordingResolver) []byte {
	t.Helper()
	select {
	case query := <-resolver.sent:
		return query
	case <-time.After(5 * time.Second):
		t.Fatal("client sent no query")
		return nil
	}
}

// A poll triggered by a response must not repeat the last data packet.
func TestClientPollAfterDataIsEmpty(t *testing.T) {
	resolver := newRecordingResolver()
	client := newHardeningClient(t, resolver)
	go client.run()
	defer client.Close()
	domain := client.domains[0]

	if _, err := client.WriteTo([]byte("payload"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if kind := queryKind(t, domain, nextQuery(t, resolver)); kind != 3 {
		t.Fatalf("first query kind = %d, want data (3)", kind)
	}
	client.poolCh <- struct{}{}
	if kind := queryKind(t, domain, nextQuery(t, resolver)); kind != 8 {
		t.Fatalf("poll after data has kind %d, want empty poll (8)", kind)
	}
}

// WriteTo reports success only for a packet it handed to a resolver. A burst
// larger than the send queue the client once had must reach the resolver
// whole instead of being dropped behind a successful return.
func TestClientHandsEveryWrittenPacketToAResolver(t *testing.T) {
	resolver := newRecordingResolver()
	client := newHardeningClient(t, resolver)
	defer close(client.closeCh)
	domain := client.domains[0]

	const burst = 32
	for i := range burst {
		if n, err := client.WriteTo([]byte{byte(i)}, &net.UDPAddr{}); n != 1 || err != nil {
			t.Fatalf("write %d = (%d, %v), want (1, nil)", i, n, err)
		}
	}
	for i := range burst {
		select {
		case query := <-resolver.sent:
			if kind := queryKind(t, domain, query); kind != 3 {
				t.Fatalf("query %d kind = %d, want data (3)", i, kind)
			}
		default:
			t.Fatalf("resolver got %d of %d written packets", i, burst)
		}
	}
}

// stalledResolver blocks every Send until it is closed, like a resolver conn
// behind dialerProxy whose writes wait for Close.
type stalledResolver struct {
	entered   chan struct{}
	enterOnce sync.Once
	closed    chan struct{}
	closeOnce sync.Once
}

func newStalledResolver() *stalledResolver {
	return &stalledResolver{entered: make(chan struct{}), closed: make(chan struct{})}
}

func (r *stalledResolver) Addr() *stdnet.UDPAddr {
	return &stdnet.UDPAddr{IP: stdnet.IP{192, 0, 2, 53}, Port: 53}
}

func (r *stalledResolver) Read([]byte) (int, error) {
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *stalledResolver) Send([]byte) {
	r.enterOnce.Do(func() { close(r.entered) })
	<-r.closed
}

func (r *stalledResolver) Close() { r.closeOnce.Do(func() { close(r.closed) }) }

// WriteTo sends synchronously, so a stalled resolver write blocks it. Closing
// the client must still reach the resolvers and release that write.
func TestClientCloseReleasesStalledWrite(t *testing.T) {
	resolver := newStalledResolver()
	t.Cleanup(resolver.Close)
	client := newHardeningClient(t, resolver)

	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = client.WriteTo([]byte("payload"), &net.UDPAddr{})
	}()
	select {
	case <-resolver.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("WriteTo never reached the resolver")
	}

	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		resolver.Close() // release the write so both goroutines finish
		<-closed
		<-written
		t.Fatal("Close blocked behind a stalled resolver write")
	}
	select {
	case <-written:
	case <-time.After(5 * time.Second):
		t.Fatal("WriteTo stayed blocked after Close")
	}
}

// XDNS reaches the network only through its resolvers. FinalMask must not open
// a base socket for it that nothing owns.
func TestFinalMaskDialOwnsEveryXDNSSocket(t *testing.T) {
	var mu sync.Mutex
	var dialed []*trackedPacketConn
	dialUDP := func(context.Context, net.Destination) (net.PacketConn, net.Addr, error) {
		conn := &trackedPacketConn{blockingPacketConn: newBlockingPacketConn()}
		mu.Lock()
		dialed = append(dialed, conn)
		mu.Unlock()
		return conn, &net.UDPAddr{IP: net.IP{192, 0, 2, 53}, Port: 53}, nil
	}
	config := &Config{
		Domains:   []*DomainProto{{Name: hardeningDomain, LenLimit: 255, LabelLimit: 63}},
		Resolvers: []*ResolverProto{{Type: "udp", Addr: "192.0.2.53:53"}},
	}
	mask := finalmask.NewFinalMask(nil, []finalmask.UDPMask{config}, nil, nil, dialUDP, nil)
	conn, err := mask.DialUDP(context.Background(), net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for i, socket := range dialed {
		if !socket.isClosed() {
			t.Fatalf("socket %d of %d dialed for XDNS was left open after Close", i+1, len(dialed))
		}
	}
}

type trackedPacketConn struct {
	*blockingPacketConn
}

func (c *trackedPacketConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// pipeDialer hands out in-memory TCP conns and keeps their peer ends.
type pipeDialer struct {
	mu    sync.Mutex
	dials int
	peers chan stdnet.Conn
	write chan struct{}
}

func newPipeDialer() *pipeDialer {
	return &pipeDialer{peers: make(chan stdnet.Conn, 8), write: make(chan struct{}, 8)}
}

func (d *pipeDialer) dialer() *finalmask.Dialer {
	return &finalmask.Dialer{DialTCP: func(net.Destination) (net.Conn, error) {
		d.mu.Lock()
		d.dials++
		port := 5300 + d.dials
		d.mu.Unlock()
		client, peer := stdnet.Pipe()
		d.peers <- peer
		return &resolverPipeConn{Conn: client, remote: &stdnet.TCPAddr{IP: stdnet.IP{192, 0, 2, 53}, Port: port}, write: d.write}, nil
	}}
}

func (d *pipeDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

type resolverPipeConn struct {
	stdnet.Conn
	remote stdnet.Addr
	write  chan struct{}
}

func (c *resolverPipeConn) RemoteAddr() stdnet.Addr { return c.remote }

func (c *resolverPipeConn) Write(p []byte) (int, error) {
	select {
	case c.write <- struct{}{}:
	default:
	}
	return c.Conn.Write(p)
}

// A DNS server that stops reading must not keep Close from tearing the
// resolver down: Close has to interrupt the stalled write.
func TestTCPResolverCloseInterruptsStalledSend(t *testing.T) {
	dialer := newPipeDialer()
	resolver, err := NewTCPResolver(&ResolverProto{Type: "tcp", Addr: "192.0.2.53:53"}, dialer.dialer())
	if err != nil {
		t.Fatal(err)
	}
	peer := <-dialer.peers
	t.Cleanup(func() { _ = peer.Close() })

	sent := make(chan struct{})
	go func() {
		defer close(sent)
		resolver.Send([]byte("query"))
	}()
	select {
	case <-dialer.write:
	case <-time.After(5 * time.Second):
		t.Fatal("Send never reached Write")
	}

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		resolver.Close()
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked behind a Send stalled on an unread TCP conn")
	}
	<-sent
}

// Addr runs on the client's receive loop while Send may redial after the
// previous conn failed; the address published by a redial must be read
// without a data race.
func TestTCPResolverRedialPublishesAddressSafely(t *testing.T) {
	dialer := newPipeDialer()
	resolver, err := NewTCPResolver(&ResolverProto{Type: "tcp", Addr: "192.0.2.53:53"}, dialer.dialer())
	if err != nil {
		t.Fatal(err)
	}
	_ = (<-dialer.peers).Close()

	var drains sync.WaitGroup
	draining := make(chan struct{})
	go func() {
		defer close(draining)
		for peer := range dialer.peers {
			drains.Go(func() { _, _ = io.Copy(io.Discard, peer) })
		}
	}()
	stop := make(chan struct{})
	stopReading := sync.OnceFunc(func() { close(stop) })
	reading := make(chan struct{})
	go func() {
		defer close(reading)
		for {
			select {
			case <-stop:
				return
			default:
				_ = resolver.Addr()
			}
		}
	}()
	// Closing the resolver closes the client ends, which ends every drain;
	// no dial can follow, so the peers channel can be closed.
	t.Cleanup(func() {
		stopReading()
		<-reading
		resolver.Close()
		close(dialer.peers)
		<-draining
		drains.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for dialer.dialCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("resolver did not redial after its conn failed")
		}
		resolver.Send([]byte("query"))
	}
	stopReading()
	<-reading
	if got := resolver.Addr(); got == nil || got.Port != 5302 {
		t.Fatalf("Addr after redial = %v, want port 5302", got)
	}
}

// stallingPacketConn blocks every write until it is closed, as a pipe-backed
// conn behind dialerProxy does when the downstream stops reading.
type stallingPacketConn struct {
	*blockingPacketConn
	writing chan struct{}
}

func (c *stallingPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	select {
	case c.writing <- struct{}{}:
	default:
	}
	<-c.closed
	return 0, io.ErrClosedPipe
}

func TestUDPResolverCloseInterruptsStalledSend(t *testing.T) {
	conn := &stallingPacketConn{blockingPacketConn: newBlockingPacketConn(), writing: make(chan struct{}, 1)}
	t.Cleanup(func() { _ = conn.Close() })
	dialer := &finalmask.Dialer{DialUDP: func(net.Destination) (net.Conn, error) {
		return &net.PacketConnWrapper{PacketConn: conn, Dest: &net.UDPAddr{IP: net.IP{192, 0, 2, 53}, Port: 53}}, nil
	}}
	resolver, err := NewUDPResolver(&ResolverProto{Type: "udp", Addr: "192.0.2.53:53"}, dialer)
	if err != nil {
		t.Fatal(err)
	}

	sent := make(chan struct{})
	go func() {
		defer close(sent)
		resolver.Send([]byte("query"))
	}()
	select {
	case <-conn.writing:
	case <-time.After(5 * time.Second):
		t.Fatal("Send never reached WriteTo")
	}

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		resolver.Close()
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked behind a Send stalled in WriteTo")
	}
	<-sent
}

// cnameTestDomain answers with CNAME records. Their payload is the only one
// that can decode to far more bytes than the response occupies on the wire:
// DNS name compression folds the suffix shared by every fragment name into a
// two-byte pointer.
func cnameTestDomain(t *testing.T) *Domain {
	t.Helper()
	domain, err := NewDomain(hardeningDomain, 255, 63, []uint16{TypeCNAME}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

// packResponse packs the answer a server sends for a query when it carries data.
func packResponse(t *testing.T, domain *Domain, qtype dnsmessage.Type, data []byte) []byte {
	t.Helper()
	query := dnsmessage.Message{Questions: []dnsmessage.Question{{
		Name:  domain.Encode(make([]byte, 17)),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}}}
	return NewResp(query, domain, 0).Encode(nil, data)
}

func unpackResp(t *testing.T, domain *Domain, packed []byte) *Resp {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	return NewResp(msg, domain, 0)
}

// Resolver replies are not authenticated and the client decodes them into a
// 4096-byte pooled buffer, so any host that can reach the client's socket can
// send a CNAME answer that fits the datagram but decodes to more than the
// buffer holds. Such a payload must be dropped, not crash the client.
func TestClientDropsCNAMEPayloadLargerThanDecodeBuffer(t *testing.T) {
	domain := cnameTestDomain(t)
	// 32 fragments: the first carries cap-2 payload bytes, the others cap-1.
	data := make([]byte, (domain.cap-2)+31*(domain.cap-1))
	packed := packResponse(t, domain, dnsmessage.TypeCNAME, data)
	if len(packed) > 4096 {
		t.Fatalf("crafted response is %d bytes; it must fit the 4096-byte receive buffer", len(packed))
	}

	client := newHardeningClient(t, newRecordingResolver())
	client.domains = []*Domain{domain}
	client.readCh = make(chan packet, 8)
	delivered := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("%d-byte response decoding to %d bytes panicked the client: %v", len(packed), len(data), recovered)
			}
		}()
		delivered = client.read(packed, &net.UDPAddr{IP: net.IP{192, 0, 2, 53}, Port: 53})
	}()
	if delivered || len(client.readCh) != 0 {
		t.Fatalf("oversized payload was accepted: read=%v, %d packets queued", delivered, len(client.readCh))
	}
}

// Resp.Decode writes into the caller's buffer and must neither outgrow it nor
// report a length beyond it: a payload of exactly len(buffer) fits, one more
// byte is rejected.
func TestRespDecodeRejectsPayloadThatDoesNotFit(t *testing.T) {
	domain, err := NewDomain(hardeningDomain, 255, 63, []uint16{TypeCNAME, TypeTXT}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeCNAME, dnsmessage.TypeTXT} {
		for _, tc := range []struct {
			size int
			want int
		}{
			{size: 4096, want: 4096},
			{size: 4097, want: 0},
		} {
			packed := packResponse(t, domain, qtype, make([]byte, tc.size))
			if got := unpackResp(t, domain, packed).Decode(make([]byte, 4096)); got != tc.want {
				t.Errorf("%v: Decode of a %d-byte payload into 4096 bytes = %d, want %d", qtype, tc.size, got, tc.want)
			}
		}
	}
}

// Guard for the bound above: a legitimate multi-fragment answer still reaches
// the reader byte for byte.
func TestClientDeliversMultiFragmentCNAMEPayload(t *testing.T) {
	domain := cnameTestDomain(t)
	payload := make([]byte, 1200)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	framed := append([]byte{0xC0 | byte(len(payload)>>8), byte(len(payload))}, payload...)
	packed := packResponse(t, domain, dnsmessage.TypeCNAME, framed)

	client := newHardeningClient(t, newRecordingResolver())
	client.domains = []*Domain{domain}
	client.readCh = make(chan packet, 8)
	if !client.read(packed, &net.UDPAddr{IP: net.IP{192, 0, 2, 53}, Port: 53}) {
		t.Fatal("legitimate response was rejected")
	}
	if len(client.readCh) != 1 {
		t.Fatalf("%d packets queued, want 1", len(client.readCh))
	}
	if got := <-client.readCh; !bytes.Equal(got.p, payload) {
		t.Fatalf("delivered %d bytes that differ from the %d sent", len(got.p), len(payload))
	}
}

// A configured domain is normalised to its absolute ASCII form. The client packs
// a query for it on every poll and treats a packing failure as fatal, so a name
// that cannot be packed must be refused when the domain is built.
func TestNewDomainNormalisesName(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{
		{"t.example", "t.example."},
		{"t.example.", "t.example."},
		{"T.Example.", "T.Example."},
		{"bücher.example", "xn--bcher-kva.example."},
		{"bücher.example.", "xn--bcher-kva.example."},
		{"xn--bcher-kva.example.", "xn--bcher-kva.example."},
	} {
		domain, err := NewDomain(tc.configured, 255, 63, []uint16{TypeTXT}, 0)
		if err != nil {
			t.Errorf("NewDomain(%q): %v", tc.configured, err)
			continue
		}
		if got := domain.name.String(); got != tc.want {
			t.Errorf("NewDomain(%q) name = %q, want %q", tc.configured, got, tc.want)
		}
		query := dnsmessage.Message{Questions: []dnsmessage.Question{{
			Name:  domain.Encode(make([]byte, 17)),
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		}}}
		packed, err := query.Pack()
		if err != nil {
			t.Errorf("poll query for %q cannot be packed: %v", tc.configured, err)
			continue
		}
		var unpacked dnsmessage.Message
		if err := unpacked.Unpack(packed); err != nil {
			t.Errorf("poll query for %q cannot be unpacked: %v", tc.configured, err)
			continue
		}
		if !domain.IsDomain(unpacked.Questions[0].Name) {
			t.Errorf("poll query for %q is not recognised as belonging to the domain", tc.configured)
		}
	}
}

// The error names the rejected domain: a config lists several, and the
// operator has to find the one that no longer loads.
func TestNewDomainRejectsNamesThatCannotBePacked(t *testing.T) {
	for _, configured := range []string{
		"",
		".",
		"..",
		".t.example",
		"t..example",
		"t.example..",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 127) + "example",
	} {
		domain, err := NewDomain(configured, 255, 63, []uint16{TypeTXT}, 0)
		if err == nil {
			t.Errorf("NewDomain(%q) = %q, want an error", configured, domain.name.String())
			continue
		}
		if quoted := fmt.Sprintf("%q", configured); !strings.Contains(err.Error(), quoted) {
			t.Errorf("NewDomain(%q) error %q does not name the domain %s", configured, err, quoted)
		}
	}
}

// The other errors that depend on the name also name it and say what is
// wrong. An internationalised name can fit in UTF-8 and outgrow 255 bytes
// only in punycode, so the length is the one of the ASCII form; and a name
// can leave too little of lenLimit for the data a query carries.
func TestNewDomainLimitErrorsNameTheDomain(t *testing.T) {
	for _, tc := range []struct {
		configured string
		lenLimit   int
		want       string
	}{
		{strings.Repeat("aü.", 30) + "example", 255, "longer than 255 bytes"},
		{"t.example", 5, "lenLimit 5"},
		{"t.example", 20, "fewer than 17"},
	} {
		_, err := NewDomain(tc.configured, tc.lenLimit, 63, []uint16{TypeTXT}, 0)
		if err == nil {
			t.Errorf("NewDomain(%q) with lenLimit %d succeeded, want an error", tc.configured, tc.lenLimit)
			continue
		}
		if quoted := fmt.Sprintf("%q", tc.configured); !strings.Contains(err.Error(), quoted) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("NewDomain(%q) with lenLimit %d: error %q, want it to name the domain and say %q", tc.configured, tc.lenLimit, err, tc.want)
		}
	}
}

// A reply to an unsupported EDNS request must still be a response: with QR
// clear the datagram is another query, which no resolver would answer with and
// which tells a prober this is not a stock DNS server.
func TestServerMarksEDNSErrorRepliesAsResponses(t *testing.T) {
	domain := hardeningTestDomain(t)
	opt := func(ttl uint32) dnsmessage.Resource {
		return dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096, TTL: ttl},
			Body:   &dnsmessage.OPTResource{},
		}
	}
	for _, tc := range []struct {
		name        string
		additionals []dnsmessage.Resource
		wantRCode   dnsmessage.RCode
		wantOPTTTL  uint32
	}{
		{name: "duplicate OPT", additionals: []dnsmessage.Resource{opt(0), opt(0)}, wantRCode: dnsmessage.RCodeFormatError},
		// RFC 6891 section 6.1.3: BADVERS is extended RCODE 16, carried as 1 in
		// the top byte of the OPT TTL and 0 in the header.
		{name: "unsupported EDNS version", additionals: []dnsmessage.Resource{opt(1 << 16)}, wantRCode: dnsmessage.RCodeSuccess, wantOPTTTL: 1 << 24},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := dnsmessage.Message{
				Questions: []dnsmessage.Question{{
					Name:  domain.Encode(make([]byte, 17)),
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
				}},
				Additionals: tc.additionals,
			}
			packed, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}

			server := &xdnsServer{domains: []*Domain{domain}, drCh: make(chan resp, 1)}
			server.read(packed, &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 53})
			var reply resp
			select {
			case reply = <-server.drCh:
			default:
				t.Fatal("server sent no reply")
			}
			wire, err := reply.msg.Pack()
			if err != nil {
				t.Fatal(err)
			}
			var got dnsmessage.Message
			if err := got.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			if !got.Header.Response {
				t.Error("reply has QR=0, it is not a response")
			}
			if got.Header.RCode != tc.wantRCode {
				t.Errorf("RCODE = %v, want %v", got.Header.RCode, tc.wantRCode)
			}
			if tc.wantOPTTTL != 0 {
				if len(got.Additionals) == 0 || got.Additionals[0].Header.TTL != tc.wantOPTTTL {
					t.Errorf("OPT = %+v, want TTL %#x", got.Additionals, tc.wantOPTTTL)
				}
			}
		})
	}
}
