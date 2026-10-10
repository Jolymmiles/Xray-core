package hysteria

import (
	"context"
	"errors"
	stdnet "net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// authServer is an HTTP/3 server that completes the QUIC handshake of
// Hysteria clients and answers their authentication. The first request gets
// firstStatus, or with firstStatus 0 waits until releaseAuth, so the dial
// that sent it keeps its client busy with no deadline of its own. Later
// requests are accepted at once.
type authServer struct {
	dest        xnet.Destination
	authStarted chan struct{} // closed when the first auth request arrives
	firstClosed chan struct{} // closed when the first QUIC connection ends
	release     chan struct{}
	releaseOnce sync.Once
	connections atomic.Int32

	mu         sync.Mutex
	firstPeer  *stdnet.UDPAddr
	firstCause error // why the first connection ended
}

func startAuthServer(t *testing.T, settings *internet.MemoryStreamConfig, firstStatus int) *authServer {
	t.Helper()
	tlsConfig := tls.ConfigFromStreamSettings(settings).GetTLSConfig(tls.WithNextProto("h3"))
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &authServer{
		dest:        xnet.TCPDestination(xnet.DomainAddress("localhost"), xnet.Port(listener.Addr().(*stdnet.UDPAddr).Port)),
		authStarted: make(chan struct{}),
		firstClosed: make(chan struct{}),
		release:     make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	var conns []*quic.Conn
	var connsMu sync.Mutex
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			first := s.connections.Add(1) == 1
			if first {
				s.mu.Lock()
				s.firstPeer = conn.RemoteAddr().(*stdnet.UDPAddr)
				s.mu.Unlock()
			}
			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					status := StatusAuthOK
					if first {
						close(s.authStarted)
						if firstStatus != 0 {
							status = firstStatus
						} else {
							select {
							case <-s.release:
							case <-r.Context().Done():
								return
							}
						}
					}
					w.WriteHeader(status)
				})}
				_ = server.ServeQUICConn(conn)
				if first {
					<-conn.Context().Done()
					s.mu.Lock()
					s.firstCause = context.Cause(conn.Context())
					s.mu.Unlock()
					close(s.firstClosed)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		s.releaseAuth()
		cancel()
		_ = listener.Close()
		<-accepted
		connsMu.Lock()
		for _, conn := range conns {
			_ = conn.CloseWithError(0, "")
		}
		connsMu.Unlock()
		workers.Wait()
	})
	return s
}

func (s *authServer) releaseAuth() {
	s.releaseOnce.Do(func() { close(s.release) })
}

// awaitAuth waits until the first dial holds its client in authentication.
func (s *authServer) awaitAuth(t *testing.T) {
	t.Helper()
	select {
	case <-s.authStarted:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the first authentication request did not reach the server")
	}
}

// awaitFirstClosed waits until the first connection ends and returns why.
func (s *authServer) awaitFirstClosed(t *testing.T) error {
	t.Helper()
	select {
	case <-s.firstClosed:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the first connection stayed open")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firstCause
}

// firstSource is the address of the client socket of the first connection.
func (s *authServer) firstSource() *stdnet.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firstPeer
}

// udpRelay relays UDP datagrams between Hysteria clients and a listener and
// records the client socket it heard first. With dropFirst it drops every
// datagram of that socket, so the dial that owns it stalls in its QUIC
// handshake while datagrams of later sockets pass. A socket error before the
// test ends fails the test, so a broken relay is not reported as a stalled
// dial only.
type udpRelay struct {
	dest      xnet.Destination
	conn      *stdnet.UDPConn
	upstream  *stdnet.UDPAddr
	dropFirst bool
	heard     chan struct{} // closed on the first datagram

	mu      sync.Mutex
	closed  bool
	failure error // the first socket error before closed
	first   *stdnet.UDPAddr
	peers   map[string]*stdnet.UDPConn
	workers sync.WaitGroup
}

func startUDPRelay(t *testing.T, listener xnet.Destination, dropFirst bool) *udpRelay {
	t.Helper()
	conn, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &udpRelay{
		dest:      xnet.TCPDestination(xnet.DomainAddress("localhost"), xnet.Port(conn.LocalAddr().(*stdnet.UDPAddr).Port)),
		conn:      conn,
		upstream:  &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: int(listener.Port)},
		dropFirst: dropFirst,
		heard:     make(chan struct{}),
		peers:     make(map[string]*stdnet.UDPConn),
	}
	r.workers.Add(1)
	go r.relay()
	t.Cleanup(func() {
		r.mu.Lock()
		r.closed = true
		failure := r.failure
		for _, peer := range r.peers {
			_ = peer.Close()
		}
		r.mu.Unlock()
		_ = conn.Close()
		r.workers.Wait()
		if failure != nil {
			t.Errorf("the UDP relay failed: %v", failure)
		}
	})
	return r
}

// fail records err unless the relay is closing, when socket errors are
// expected.
func (r *udpRelay) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failLocked(err)
}

func (r *udpRelay) failLocked(err error) {
	if !r.closed && r.failure == nil {
		r.failure = err
	}
}

func (r *udpRelay) relay() {
	defer r.workers.Done()
	buf := make([]byte, 65535)
	for {
		n, source, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			r.fail(err)
			return
		}
		if peer := r.peerFor(source); peer != nil {
			if _, err := peer.Write(buf[:n]); err != nil {
				r.fail(err)
			}
		}
	}
}

// peerFor returns the upstream socket that carries the datagrams of source,
// or nil when the relay drops them or has stopped.
func (r *udpRelay) peerFor(source *stdnet.UDPAddr) *stdnet.UDPConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.first == nil {
		r.first = source
		close(r.heard)
	}
	if r.dropFirst && r.first.String() == source.String() {
		return nil
	}
	if peer := r.peers[source.String()]; peer != nil {
		return peer
	}
	peer, err := stdnet.DialUDP("udp4", nil, r.upstream)
	if err != nil {
		r.failLocked(err)
		return nil
	}
	r.peers[source.String()] = peer
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		buf := make([]byte, 65535)
		for {
			n, err := peer.Read(buf)
			if err != nil {
				r.fail(err)
				return
			}
			if _, err := r.conn.WriteToUDP(buf[:n], source); err != nil {
				r.fail(err)
			}
		}
	}()
	return peer
}

// awaitFirst waits for the first datagram and returns the address of the
// socket that sent it.
func (r *udpRelay) awaitFirst(t *testing.T) *stdnet.UDPAddr {
	t.Helper()
	select {
	case <-r.heard:
	case <-time.After(cleanupTestDeadline):
		r.mu.Lock()
		failure := r.failure
		r.mu.Unlock()
		t.Fatalf("the relay heard no datagram (relay error: %v)", failure)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.first
}

type dialResult struct {
	conn stat.Connection
	err  error
}

// pendingDial is a dial running on another goroutine. The test joins it and
// closes the connection it returns when the test ends, after unblock.
type pendingDial struct {
	result  chan dialResult
	unblock func()
	r       dialResult
	done    bool
}

// dialAsync dials through m on another goroutine. unblock must let a stalled
// dial return; it runs before the dial is joined on a failure path.
func (m *testClientManager) dialAsync(t *testing.T, ctx context.Context, network string, dest xnet.Destination, unblock func()) *pendingDial {
	t.Helper()
	d := &pendingDial{result: make(chan dialResult, 1), unblock: unblock}
	go func() {
		var r dialResult
		if network == "udp" {
			r.conn, r.err = m.dialUDP(ctx, dest)
		} else {
			r.conn, r.err = m.dialTCP(ctx, dest)
		}
		d.result <- r
	}()
	t.Cleanup(func() {
		if !d.done {
			d.unblock()
			select {
			case r := <-d.result:
				d.r, d.done = r, true
			case <-time.After(cleanupTestDeadline):
				t.Errorf("a dial did not return within %v", cleanupTestDeadline)
			}
		}
		if d.r.conn != nil {
			_ = d.r.conn.Close()
		}
	})
	return d
}

// await waits for the dial to return. On a deadline it unblocks the dial and
// fails the test; the dial is joined when the test ends.
func (d *pendingDial) await(t *testing.T, dial string) dialResult {
	t.Helper()
	select {
	case r := <-d.result:
		d.r, d.done = r, true
		return r
	case <-time.After(cleanupTestDeadline):
		d.unblock()
		t.Fatalf("%s did not return within %v", dial, cleanupTestDeadline)
		return dialResult{}
	}
}

func noUnblock() {}

// clientHTTP3Goroutines returns the stacks, by goroutine header, of the
// goroutines of HTTP/3 client transports and connections: the dial, request
// and stream goroutines a Hysteria dial starts while it authenticates.
func clientHTTP3Goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	goroutines := make(map[string]string)
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "http3.(*ClientConn)") || strings.Contains(g, "http3.(*Transport)") {
			header, _, _ := strings.Cut(g, " [")
			goroutines[header] = g
		}
	}
	return goroutines
}

// awaitNoNewClientHTTP3Goroutines waits until every such goroutine missing
// from before has exited. A released goroutine exits on its own schedule, so
// the stacks are polled until the deadline.
func awaitNoNewClientHTTP3Goroutines(t *testing.T, before map[string]string) {
	t.Helper()
	deadline := time.NewTimer(cleanupTestDeadline)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		var left []string
		for header, stack := range clientHTTP3Goroutines() {
			if _, ok := before[header]; !ok {
				left = append(left, stack)
			}
		}
		if len(left) == 0 {
			return
		}
		select {
		case <-poll.C:
		case <-deadline.C:
			t.Fatalf("%d HTTP/3 client goroutines left; one of them:\n%s", len(left), left[0])
		}
	}
}

// XTLS/Xray-core#7119: a dial waiting for a client that another dial holds
// through its handshake ignored its context. A closed SOCKS5 UDP association
// or an abandoned TCP request kept a goroutine queued on the client until the
// holder finished, and then dialed for nobody. The waiter must return with
// its context's error without dialing, and the holder must finish its dial.
func TestCanceledDialStopsWaitingForBusyClient(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, cancellation := range []string{"cancel", "deadline"} {
			t.Run(network+"/"+cancellation, func(t *testing.T) {
				settings := hysteriaTestSettings(t)
				server := startAuthServer(t, settings, 0)
				m := newTestClientManager(t, settings)

				holder := m.dialAsync(t, context.Background(), "udp", server.dest, server.releaseAuth)
				server.awaitAuth(t)

				ctx, cancel := context.WithCancel(context.Background())
				want := context.Canceled
				if cancellation == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
					want = context.DeadlineExceeded
				}
				defer cancel()
				waiter := m.dialAsync(t, ctx, network, server.dest, server.releaseAuth)
				if cancellation == "cancel" {
					cancel()
				}
				if r := waiter.await(t, "a canceled dial waiting for a busy client"); !errors.Is(r.err, want) {
					t.Fatalf("a canceled dial waiting for a busy client returned %v, want %v", r.err, want)
				}
				if n := server.connections.Load(); n != 1 {
					t.Fatalf("the server saw %d connections, want only the holder's", n)
				}

				server.releaseAuth()
				if r := holder.await(t, "the holder"); r.err != nil {
					t.Fatalf("the holder failed after a waiter gave up: %v", r.err)
				}
				if c := m.pooled(server.dest); c == nil || c.resources().conn == nil {
					t.Fatal("the holder did not connect the pooled client")
				}
			})
		}
	}
}

// A dial whose context is already done must fail without a stream or a
// socket, whether its client is connected or not: a free client lock and a
// done context are both ready, and the lock alone must not decide.
func TestCanceledDialGetsNoConnection(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, network := range []string{"tcp", "udp"} {
		t.Run("ready client/"+network, func(t *testing.T) {
			settings := hysteriaTestSettings(t)
			dest := startEchoListener(t, settings)
			m := newTestClientManager(t, settings)
			m.echo(t, context.Background(), dest, "connect")
			c := m.pooled(dest)
			connected := c.resources().conn

			for range 16 {
				r := m.dialAsync(t, canceled, network, dest, noUnblock).await(t, "a canceled dial")
				if !errors.Is(r.err, context.Canceled) {
					t.Fatalf("a canceled dial on a ready client returned %v, want %v", r.err, context.Canceled)
				}
			}
			if c.resources().conn != connected {
				t.Fatal("a canceled dial replaced the connection")
			}
			m.echo(t, context.Background(), dest, "after canceled dials")
		})
		t.Run("new client/"+network, func(t *testing.T) {
			settings := hysteriaTestSettings(t)
			relay := startUDPRelay(t, startEchoListener(t, settings), false)
			m := newTestClientManager(t, settings)

			r := m.dialAsync(t, canceled, network, relay.dest, noUnblock).await(t, "a canceled dial")
			if !errors.Is(r.err, context.Canceled) {
				t.Fatalf("a canceled dial on a new client returned %v, want %v", r.err, context.Canceled)
			}
			if remaining := m.pooled(relay.dest).resources(); remaining.conn != nil || remaining.pktConn != nil {
				t.Fatal("a canceled dial connected the client")
			}

			// On loopback a datagram is queued at the relay when it is sent,
			// so the relay hears the canceled dial first if it sent anything.
			r = m.dialAsync(t, context.Background(), "tcp", relay.dest, noUnblock).await(t, "a dial after a canceled one")
			if r.err != nil {
				t.Fatal(r.err)
			}
			exchange(t, r.conn, "after a canceled dial")
			if first, local := relay.awaitFirst(t), r.conn.LocalAddr().(*stdnet.UDPAddr); first.Port != local.Port {
				t.Fatalf("the relay first heard %v, not the live dial's socket %v: the canceled dial sent a datagram", first, local)
			}
		})
	}
}

// XTLS/Xray-core#7119: the dial that holds a client ran its QUIC handshake
// without its context, so canceling it changed nothing until the handshake
// timed out. Canceling must stop that handshake and release its socket, and a
// dial waiting for the same client must then connect on its own.
func TestCanceledDialAbortsItsHandshake(t *testing.T) {
	settings := hysteriaTestSettings(t)
	relay := startUDPRelay(t, startEchoListener(t, settings), true)
	m := newTestClientManager(t, settings)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	holder := m.dialAsync(t, ctx, "tcp", relay.dest, cancel)
	socket := relay.awaitFirst(t)

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	defer cancelWaiter()
	waiter := m.dialAsync(t, waiterCtx, "tcp", relay.dest, cancelWaiter)

	cancel()
	if r := holder.await(t, "a canceled dial in its handshake"); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("a canceled dial in its handshake returned %v, want %v", r.err, context.Canceled)
	}

	r := waiter.await(t, "the waiting dial")
	if r.err != nil {
		t.Fatalf("the waiting dial failed after the holder gave up: %v", r.err)
	}
	exchange(t, r.conn, "after a canceled handshake")
	// The waiter's socket may reuse the port the holder released.
	if r.conn.LocalAddr().(*stdnet.UDPAddr).Port != socket.Port {
		assertHysteriaUDPPortAvailable(t, socket.Port)
	}
	c := m.pooled(relay.dest)
	if c == nil {
		t.Fatal("the pool holds no client after a dial")
	}
	connected := c.resources().conn

	// The connection outlives the context of the dial that opened it: later
	// dials share it.
	cancelWaiter()
	m.echo(t, context.Background(), relay.dest, "after the connecting dial ended")
	if c.resources().conn != connected {
		t.Fatal("ending the dial that connected the client replaced its connection")
	}
	select {
	case <-connected.Context().Done():
		t.Fatal("ending the dial that connected the client closed its connection")
	default:
	}
}

// XTLS/Xray-core#7119: the authentication request ignored the dial's context,
// so a dial whose server stalled after the handshake held the client until
// the connection idled out. Canceling must close the provisional connection
// and socket without publishing them, and the client must connect again.
func TestCanceledDialAbortsItsAuthentication(t *testing.T) {
	settings := hysteriaTestSettings(t)
	server := startAuthServer(t, settings, 0)
	m := newTestClientManager(t, settings)
	before := clientHTTP3Goroutines()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	holder := m.dialAsync(t, ctx, "udp", server.dest, server.releaseAuth)
	server.awaitAuth(t)
	cancel()
	if r := holder.await(t, "a canceled dial in authentication"); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("a canceled dial in authentication returned %v, want %v", r.err, context.Canceled)
	}

	server.awaitFirstClosed(t)
	c := m.pooled(server.dest)
	if c == nil {
		t.Fatal("the pool holds no client after a dial")
	}
	if remaining := c.resources(); remaining.conn != nil || remaining.pktConn != nil {
		t.Fatal("a canceled dial published its provisional connection")
	}
	assertHysteriaUDPPortAvailable(t, server.firstSource().Port)
	awaitNoNewClientHTTP3Goroutines(t, before)

	if r := m.dialAsync(t, context.Background(), "tcp", server.dest, noUnblock).await(t, "a dial after a canceled one"); r.err != nil {
		t.Fatalf("a dial after a canceled authentication failed: %v", r.err)
	}
	if c.resources().conn == nil {
		t.Fatal("a dial after a canceled authentication did not connect the client")
	}
}

// A rejected authentication left the response unread and the request on the
// background context, so the HTTP/3 goroutine watching that request never
// returned: every dial with a wrong password leaked one.
func TestRejectedAuthenticationLeaksNoGoroutine(t *testing.T) {
	settings := hysteriaTestSettings(t)
	dest := startEchoListener(t, settings)
	wrong := *settings
	wrong.ProtocolSettings = &Config{Auth: "wrong"}
	m := newTestClientManager(t, &wrong)
	before := clientHTTP3Goroutines()

	// Keep the dials' contexts alive: a client stays up while its user waits.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range 3 {
		r := m.dialAsync(t, ctx, "tcp", dest, noUnblock).await(t, "a dial with a wrong password")
		if r.err == nil || !strings.HasSuffix(r.err.Error(), "auth failed code 404") {
			t.Fatalf("a dial with a wrong password returned %v, want auth failed code 404", r.err)
		}
	}
	if c := m.pooled(dest); c == nil || c.resources().conn != nil {
		t.Fatal("a rejected dial published its connection")
	}
	awaitNoNewClientHTTP3Goroutines(t, before)
}

// A client that the server rejects closes its connection with
// H3_GENERAL_PROTOCOL_ERROR, as the official Hysteria client does. The fork
// closes the connection before releasing the HTTP/3 transport, whose Close
// would otherwise close it first with code 0 (docs/FORK.md).
func TestRejectedAuthenticationClosesWithProtocolError(t *testing.T) {
	settings := hysteriaTestSettings(t)
	server := startAuthServer(t, settings, http.StatusForbidden)
	m := newTestClientManager(t, settings)

	r := m.dialAsync(t, context.Background(), "tcp", server.dest, noUnblock).await(t, "a rejected dial")
	if r.err == nil || !strings.HasSuffix(r.err.Error(), "auth failed code 403") {
		t.Fatalf("a rejected dial returned %v, want auth failed code 403", r.err)
	}
	var closed *quic.ApplicationError
	if cause := server.awaitFirstClosed(t); !errors.As(cause, &closed) || !closed.Remote || closed.ErrorCode != closeErrCodeProtocolError {
		t.Fatalf("a rejected client closed its connection with %v, want remote application error %#x", cause, closeErrCodeProtocolError)
	}
}

// A cleaner pass waits for a client whose dial holds it. When that dial is
// canceled, the pass must go on at once: on a stalled server it otherwise
// waited until the connection idled out, and no later pass ran meanwhile. A
// dial canceled while queued behind the pass must not reconnect the client.
func TestCleanerWaitingForCanceledDialFinishes(t *testing.T) {
	settings := hysteriaTestSettings(t)
	server := startAuthServer(t, settings, 0)
	m := newTestClientManager(t, settings)
	instance := startCleanupTestInstance(t)

	ctx, cancel := context.WithCancel(instanceContext(instance))
	defer cancel()
	holder := m.dialAsync(t, ctx, "tcp", server.dest, server.releaseAuth)
	server.awaitAuth(t)
	c := m.pooled(server.dest)
	if c == nil {
		t.Fatal("the pool holds no client after a dial")
	}
	closeOutsidePool(t, c)
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}

	reached := make(chan struct{})
	m.cleaning = func(cleaned *client) {
		if cleaned == c {
			close(reached)
		}
	}
	swept := make(chan struct{})
	go func() {
		defer close(swept)
		m.cleanOnce()
	}()
	t.Cleanup(func() {
		server.releaseAuth()
		joinWithin(t, swept, "the cleaner pass")
	})
	select {
	case <-reached:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the cleaner did not reach the busy client")
	}

	queuedCtx, cancelQueued := context.WithCancel(instanceContext(instance))
	defer cancelQueued()
	queued := m.dialAsync(t, queuedCtx, "udp", server.dest, server.releaseAuth)
	cancelQueued()
	if r := queued.await(t, "a canceled dial queued behind the cleaner"); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("a canceled dial queued behind the cleaner returned %v, want %v", r.err, context.Canceled)
	}

	cancel()
	if r := holder.await(t, "a canceled dial the cleaner waits for"); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("a canceled dial the cleaner waits for returned %v, want %v", r.err, context.Canceled)
	}
	select {
	case <-swept:
	case <-time.After(cleanupTestDeadline):
		server.releaseAuth()
		t.Fatal("the cleaner pass did not finish after the dial it waited for was canceled")
	}
	if m.pooled(server.dest) != nil {
		t.Fatal("the pass kept the client of the stopped instance")
	}
	if remaining := c.resources(); remaining.conn != nil || remaining.pktConn != nil {
		t.Fatal("the client of the stopped instance holds a connection")
	}
	assertHysteriaUDPPortAvailable(t, server.firstSource().Port)
	if conn, err := c.tcp(context.Background()); err == nil {
		_ = conn.Close()
		t.Fatal("the removed client accepted a dial")
	}
	if n := server.connections.Load(); n != 1 {
		t.Fatalf("the server saw %d connections, want only the canceled holder's", n)
	}
}
