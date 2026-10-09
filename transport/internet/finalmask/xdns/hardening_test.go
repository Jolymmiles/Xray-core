package xdns

import (
	"context"
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
	if len(manager.m) != 0 || len(manager.sizem) != 0 {
		t.Fatalf("after reassembly: %d fragment entries, %d client counters; want none", len(manager.m), len(manager.sizem))
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
		sendCh:        make(chan []byte, 16),
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

// When nothing drains the send queue, WriteTo must report the lost packet
// instead of claiming success.
func TestClientReportsFullSendQueue(t *testing.T) {
	client := newHardeningClient(t, newRecordingResolver())
	defer close(client.closeCh)
	for i := range cap(client.sendCh) {
		if _, err := client.WriteTo([]byte{byte(i)}, &net.UDPAddr{}); err != nil {
			t.Fatalf("write %d into a free queue: %v", i, err)
		}
	}
	if n, err := client.WriteTo([]byte("overflow"), &net.UDPAddr{}); n != 0 || err == nil {
		t.Fatalf("WriteTo on a full queue = (%d, %v), want (0, error)", n, err)
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

func TestNewDomainRejectsNamesThatCannotBePacked(t *testing.T) {
	for _, configured := range []string{
		"",
		".",
		"..",
		".t.example",
		"t..example",
		"t.example..",
		strings.Repeat("a", 64) + ".example",
	} {
		if domain, err := NewDomain(configured, 255, 63, []uint16{TypeTXT}, 0); err == nil {
			t.Errorf("NewDomain(%q) = %q, want an error", configured, domain.name.String())
		}
	}
}
