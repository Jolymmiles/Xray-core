package hysteria

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// cleanupTestDeadline bounds every wait in these tests. It is a failure
// deadline, not a latency budget: the awaited events happen on loopback.
const cleanupTestDeadline = 10 * time.Second

// instanceContext returns a context that carries instance, as the contexts
// of outbound dials do.
func instanceContext(instance *core.Instance) context.Context {
	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func startCleanupTestInstance(t *testing.T) *core.Instance {
	t.Helper()
	instance := new(core.Instance)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

// startEchoListener starts a Hysteria listener that echoes every TCP stream
// until the test ends.
func startEchoListener(t *testing.T, settings *internet.MemoryStreamConfig) xnet.Destination {
	t.Helper()
	port := reserveHysteriaUDPPort(t)
	listener, err := Listen(context.Background(), xnet.LocalHostIP, xnet.Port(port), settings, func(conn stat.Connection) {
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return xnet.TCPDestination(xnet.DomainAddress("localhost"), xnet.Port(port))
}

// testClientManager is a client pool without the background cleaner, so a
// test decides when cleanOnce runs.
type testClientManager struct {
	*clientManager
	settings  *internet.MemoryStreamConfig
	tlsConfig *tls.Config
}

func newTestClientManager(t *testing.T, settings *internet.MemoryStreamConfig) *testClientManager {
	t.Helper()
	m := &testClientManager{
		clientManager: &clientManager{m: make(map[dialerConf]*client)},
		settings:      settings,
		tlsConfig:     tls.ConfigFromStreamSettings(settings),
	}
	t.Cleanup(func() {
		m.Lock()
		defer m.Unlock()
		for _, c := range m.m {
			c.lock <- struct{}{}
			if c.conn != nil {
				c.close()
			}
			c.unlock()
		}
	})
	return m
}

func (m *testClientManager) dialTCP(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	return m.dial(ctx, dest, m.settings, m.tlsConfig)
}

func (m *testClientManager) dialUDP(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	return m.dial(ContextWithDatagram(ctx, true), dest, m.settings, m.tlsConfig)
}

// pooled returns the client the pool holds for dest, or nil.
func (m *testClientManager) pooled(dest xnet.Destination) *client {
	dest.Network = xnet.Network_UDP
	m.RLock()
	defer m.RUnlock()
	return m.m[dialerConf{dest, m.settings}]
}

// echoOver carries payload over conn to the echo listener and back.
func echoOver(conn stat.Connection, payload string) error {
	if err := conn.SetDeadline(time.Now().Add(cleanupTestDeadline)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return err
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		return err
	}
	if string(echoed) != payload {
		return fmt.Errorf("echo returned %q, want %q", echoed, payload)
	}
	return nil
}

// exchange proves that conn carries payload to the echo listener and back.
func exchange(t *testing.T, conn stat.Connection, payload string) {
	t.Helper()
	if err := echoOver(conn, payload); err != nil {
		t.Fatal(err)
	}
}

// dialEcho dials dest through m, carries payload to the echo listener and
// back, and closes the stream on every path. It reports failure as an error,
// so worker goroutines can call it.
func (m *testClientManager) dialEcho(ctx context.Context, dest xnet.Destination, payload string) error {
	stream, err := m.dialTCP(ctx, dest)
	if err != nil {
		return fmt.Errorf("dial for %q: %w", payload, err)
	}
	if err := echoOver(stream, payload); err != nil {
		_ = stream.Close()
		return err
	}
	return stream.Close()
}

// echo dials dest through m, proves an echo exchange and closes the stream.
func (m *testClientManager) echo(t *testing.T, ctx context.Context, dest xnet.Destination, payload string) {
	t.Helper()
	if err := m.dialEcho(ctx, dest, payload); err != nil {
		t.Fatal(err)
	}
}

// joinWithin waits for a worker to report on done and reports one that does
// not finish within cleanupTestDeadline.
func joinWithin[T any](t *testing.T, done <-chan T, worker string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(cleanupTestDeadline):
		t.Errorf("%s did not finish within %v", worker, cleanupTestDeadline)
	}
}

// clientResources are the transport objects of a connected client.
type clientResources struct {
	conn    *quic.Conn
	pktConn xnet.PacketConn
}

func (c *client) resources() clientResources {
	c.lock <- struct{}{}
	defer c.unlock()
	return clientResources{conn: c.conn, pktConn: c.pktConn}
}

// stoppedInstanceClient is a pooled client whose instance has stopped,
// after one cleaner pass.
type stoppedInstanceClient struct {
	m         *testClientManager
	dest      xnet.Destination
	client    *client
	resources clientResources
	stream    stat.Connection
	session   stat.Connection
}

// newStoppedInstanceClient connects a client owned by a started instance,
// opens a TCP stream and a UDP session on it, stops the instance and runs
// one cleaner pass.
func newStoppedInstanceClient(t *testing.T) *stoppedInstanceClient {
	t.Helper()
	settings := hysteriaTestSettings(t)
	dest := startEchoListener(t, settings)
	m := newTestClientManager(t, settings)
	instance := startCleanupTestInstance(t)
	ctx := instanceContext(instance)

	stream, err := m.dialTCP(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	exchange(t, stream, "before stop")

	session, err := m.dialUDP(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })

	c := m.pooled(dest)
	if c == nil {
		t.Fatal("the pool holds no client after a dial")
	}
	resources := c.resources()
	if resources.conn == nil || resources.pktConn == nil {
		t.Fatal("the pooled client is not connected after a dial")
	}

	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	m.cleanOnce()

	return &stoppedInstanceClient{
		m:         m,
		dest:      dest,
		client:    c,
		resources: resources,
		stream:    stream,
		session:   session,
	}
}

// XTLS/Xray-core#7100: the pool is process-wide, so connections of a stopped
// instance stayed open, sending keepalives, until the process exited.
func TestCleanerClosesAndRemovesClientsOfStoppedInstance(t *testing.T) {
	stopped := newStoppedInstanceClient(t)

	if c := stopped.m.pooled(stopped.dest); c != nil {
		t.Fatal("the pool still holds the client of a stopped instance")
	}
	if remaining := stopped.client.resources(); remaining.conn != nil || remaining.pktConn != nil {
		t.Fatal("the client of a stopped instance still holds its connection")
	}
	select {
	case <-stopped.resources.conn.Context().Done():
	default:
		t.Fatal("the QUIC connection of a stopped instance is still open")
	}
	if _, err := stopped.resources.pktConn.WriteTo([]byte{0}, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 9}); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("the UDP socket of a stopped instance accepts writes: %v", err)
	}

	var payload [1]byte
	if _, err := stopped.stream.Read(payload[:]); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a stream of a stopped instance did not fail with a closed connection: %v", err)
	}

	sessionRead := make(chan error, 1)
	go func() {
		_, err := stopped.session.Read(payload[:])
		sessionRead <- err
	}()
	select {
	case err := <-sessionRead:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("a UDP session of a stopped instance failed with %v, want EOF", err)
		}
	case <-time.After(cleanupTestDeadline):
		t.Fatal("a UDP session of a stopped instance stayed open")
	}
}

// A dial may take a client from the pool just before the cleaner removes it.
// That client must refuse to reconnect: a connection it opened would belong
// to no pool and nothing would ever close it. It must refuse without a pool
// lock, which the cleaner may hold; the test holds both its own pool and the
// process-wide one.
func TestRemovedClientRefusesDialsWithoutPoolLock(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			stopped := newStoppedInstanceClient(t)

			pool := processPool()
			stopped.m.Lock()
			pool.Lock()
			var unlock sync.Once
			release := func() {
				unlock.Do(func() {
					pool.Unlock()
					stopped.m.Unlock()
				})
			}
			t.Cleanup(release)

			dialed := make(chan error, 1)
			go func() {
				var conn stat.Connection
				var err error
				if network == "tcp" {
					conn, err = stopped.client.tcp(context.Background())
				} else {
					conn, err = stopped.client.udp(context.Background())
				}
				if conn != nil {
					_ = conn.Close()
				}
				dialed <- err
			}()

			select {
			case err := <-dialed:
				if err == nil {
					t.Fatal("a removed client of a stopped instance accepted a dial")
				}
			case <-time.After(cleanupTestDeadline):
				release()
				joinWithin(t, dialed, "the dial")
				t.Fatal("a removed client waited for the pool lock")
			}
			release()

			if remaining := stopped.client.resources(); remaining.conn != nil {
				t.Fatal("a removed client opened a new connection")
			}
		})
	}
}

// Cleaning must not tear down the clients of a running instance, nor those
// dialed without an instance, and a client whose connection died must
// reconnect on the next dial.
func TestCleanerKeepsAndResetsClientsOfRunningInstances(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func(*testing.T) context.Context
	}{
		{"running instance", func(t *testing.T) context.Context { return instanceContext(startCleanupTestInstance(t)) }},
		{"no instance", func(*testing.T) context.Context { return context.Background() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := hysteriaTestSettings(t)
			dest := startEchoListener(t, settings)
			m := newTestClientManager(t, settings)
			ctx := tc.ctx(t)

			m.echo(t, ctx, dest, "first")
			c := m.pooled(dest)
			if c == nil {
				t.Fatal("the pool holds no client after a dial")
			}
			first := c.resources().conn

			m.cleanOnce()
			if m.pooled(dest) != c || c.resources().conn != first {
				t.Fatal("cleaning dropped a live client")
			}

			_ = first.CloseWithError(closeErrCodeOK, "")
			m.cleanOnce()
			if m.pooled(dest) != c {
				t.Fatal("cleaning removed a client whose connection died")
			}
			if c.resources().conn != nil {
				t.Fatal("cleaning kept a dead connection")
			}

			m.echo(t, ctx, dest, "after reset")
			if second := c.resources().conn; second == nil || second == first {
				t.Fatal("a reset client did not open a new connection")
			}
		})
	}
}

// The cleaner may wait for a client whose dial holds the client lock, for as
// long as a handshake takes. Meanwhile dials through other clients must
// proceed, both through clients already in the pool and through new ones:
// the cleaner must not hold the pool lock while it waits.
func TestCleanerWaitingForOneClientDoesNotBlockOthers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		newClient bool
	}{
		{"ready client", false},
		{"new client", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := hysteriaTestSettings(t)
			dest := startEchoListener(t, settings)
			m := newTestClientManager(t, settings)
			ctx := instanceContext(startCleanupTestInstance(t))

			m.echo(t, ctx, dest, "ready")
			target := dest
			if tc.newClient {
				target = startEchoListener(t, settings)
			}

			// No dial reaches this destination, so its key cannot collide
			// with a listener's.
			slowDest := xnet.UDPDestination(xnet.DomainAddress("stalled.invalid"), dest.Port)
			slow := &client{lock: make(chan struct{}, 1)}
			m.Lock()
			m.m[dialerConf{slowDest, settings}] = slow
			m.Unlock()

			slow.lock <- struct{}{}
			var unlock sync.Once
			release := func() { unlock.Do(slow.unlock) }
			t.Cleanup(release)

			reached := make(chan struct{})
			m.cleaning = func(c *client) {
				if c == slow {
					close(reached)
				}
			}
			swept := make(chan struct{})
			go func() {
				defer close(swept)
				m.cleanOnce()
			}()
			t.Cleanup(func() {
				release()
				joinWithin(t, swept, "the cleaner pass")
			})

			select {
			case <-reached:
			case <-time.After(cleanupTestDeadline):
				t.Fatal("the cleaner did not reach the stalled client")
			}

			dialed := make(chan error, 1)
			go func() { dialed <- m.dialEcho(ctx, target, "while the cleaner waits") }()
			select {
			case err := <-dialed:
				if err != nil {
					t.Fatalf("a dial through a %s failed while the cleaner waited: %v", tc.name, err)
				}
			case <-time.After(cleanupTestDeadline):
				release()
				joinWithin(t, dialed, "the dial")
				t.Fatalf("a dial through a %s waited for the cleaner", tc.name)
			}
		})
	}
}

// closeBlockingFeature is a feature whose Close waits until the test
// unblocks it, as app/geodata's Close waits for a download through an
// outbound to finish.
type closeBlockingFeature struct {
	closing     chan struct{}
	release     chan struct{}
	closingOnce sync.Once
	releaseOnce sync.Once
}

func newCloseBlockingFeature() *closeBlockingFeature {
	return &closeBlockingFeature{
		closing: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (*closeBlockingFeature) Type() interface{} { return (*closeBlockingFeature)(nil) }

func (*closeBlockingFeature) Start() error { return nil }

func (f *closeBlockingFeature) Close() error {
	f.closingOnce.Do(func() { close(f.closing) })
	<-f.release
	return nil
}

func (f *closeBlockingFeature) unblock() {
	f.releaseOnce.Do(func() { close(f.release) })
}

// An instance holds its status lock while its features start or close, and
// a feature may wait for an outbound dial meanwhile, as app/geodata's Close
// waits for a download. The cleaner must not hold the pool lock while it
// waits for that status: a dial that needs the pool lock would stall until
// the instance finished closing, and an instance waiting for that dial would
// never finish.
func TestCleanerWaitingForInstanceStatusDoesNotBlockDials(t *testing.T) {
	settings := hysteriaTestSettings(t)
	dest := startEchoListener(t, settings)
	newDest := startEchoListener(t, settings)
	m := newTestClientManager(t, settings)

	feature := newCloseBlockingFeature()
	instance := new(core.Instance)
	if err := instance.AddFeature(feature); err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		feature.unblock()
		_ = instance.Close()
	})

	m.echo(t, instanceContext(instance), dest, "before close")
	owned := m.pooled(dest)
	if owned == nil {
		t.Fatal("the pool holds no client after a dial")
	}

	closeErr := make(chan error, 1)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		closeErr <- instance.Close()
	}()
	t.Cleanup(func() {
		feature.unblock()
		joinWithin(t, closed, "the instance close")
	})
	select {
	case <-feature.closing:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the instance did not start closing its features")
	}

	reached := make(chan struct{})
	m.cleaning = func(c *client) {
		if c == owned {
			close(reached)
		}
	}
	swept := make(chan struct{})
	go func() {
		defer close(swept)
		m.cleanOnce()
	}()
	t.Cleanup(func() {
		feature.unblock()
		joinWithin(t, swept, "the cleaner pass")
	})
	select {
	case <-reached:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the cleaner did not reach the client of the closing instance")
	}

	running := instanceContext(startCleanupTestInstance(t))
	dialed := make(chan error, 1)
	go func() { dialed <- m.dialEcho(running, newDest, "while another instance closes") }()
	select {
	case err := <-dialed:
		if err != nil {
			t.Fatalf("a dial of a running instance failed while another instance was closing: %v", err)
		}
	case <-time.After(cleanupTestDeadline):
		feature.unblock()
		joinWithin(t, dialed, "the dial")
		t.Fatal("a dial of a running instance to a new destination waited for another instance to finish closing")
	}

	feature.unblock()
	select {
	case <-closed:
		if err := <-closeErr; err != nil {
			t.Fatal(err)
		}
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the instance did not finish closing")
	}
	select {
	case <-swept:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the cleaner pass did not finish after the instance closed")
	}
	if m.pooled(dest) != nil {
		t.Fatal("the pass kept the client of the stopped instance")
	}
	if remaining := owned.resources(); remaining.conn != nil || remaining.pktConn != nil {
		t.Fatal("the client of the stopped instance still holds its connection")
	}
	if m.pooled(newDest) == nil {
		t.Fatal("the pass dropped the client of a new destination")
	}
}

// closeOutsidePool registers the release of a client the pool may no longer
// hold, so a failing test does not leave its connection open.
func closeOutsidePool(t *testing.T, c *client) {
	t.Helper()
	t.Cleanup(func() {
		c.lock <- struct{}{}
		defer c.unlock()
		if c.conn != nil {
			c.close()
		}
	})
}

// Cleaner passes may overlap, as CleanPooledClients overlaps the background
// cleaner. A pass that captured a forced client must not remove the
// replacement that a dial added under the same key after another pass
// removed that client.
func TestConcurrentCleanersKeepReplacementClients(t *testing.T) {
	settings := hysteriaTestSettings(t)
	dest := startEchoListener(t, settings)
	m := newTestClientManager(t, settings)

	stopped := startCleanupTestInstance(t)
	m.echo(t, instanceContext(stopped), dest, "before stop")
	old := m.pooled(dest)
	if old == nil {
		t.Fatal("the pool holds no client after a dial")
	}
	closeOutsidePool(t, old)
	if err := stopped.Close(); err != nil {
		t.Fatal(err)
	}

	var oldCaptures atomic.Int32
	reached := make(chan struct{})
	resume := make(chan struct{})
	var resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(resume) }) }
	m.cleaning = func(c *client) {
		if c == old && oldCaptures.Add(1) == 1 {
			close(reached)
			<-resume
		}
	}

	stale := make(chan struct{})
	go func() {
		defer close(stale)
		m.cleanOnce()
	}()
	t.Cleanup(func() {
		release()
		joinWithin(t, stale, "the stale cleaner pass")
	})
	select {
	case <-reached:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the stale pass did not reach the client of the stopped instance")
	}

	removed := make(chan struct{})
	go func() {
		defer close(removed)
		m.cleanOnce()
	}()
	t.Cleanup(func() {
		release()
		joinWithin(t, removed, "the second cleaner pass")
	})
	select {
	case <-removed:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("a cleaner pass did not finish while another pass waited")
	}
	if m.pooled(dest) != nil {
		t.Fatal("the second pass kept the client of the stopped instance")
	}

	running := instanceContext(startCleanupTestInstance(t))
	m.echo(t, running, dest, "replacement")
	replacement := m.pooled(dest)
	if replacement == nil || replacement == old {
		t.Fatal("a dial after the removal did not add a replacement client")
	}
	closeOutsidePool(t, replacement)

	release()
	select {
	case <-stale:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the stale pass did not finish")
	}
	if m.pooled(dest) != replacement {
		t.Fatal("the stale pass removed the replacement client")
	}
	m.echo(t, running, dest, "after the stale pass")

	for _, dial := range []func(context.Context) (stat.Connection, error){old.tcp, old.udp} {
		conn, err := dial(context.Background())
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatal("the removed client accepted a dial")
		}
	}
	if old.resources().conn != nil {
		t.Fatal("the removed client opened a new connection")
	}
}
