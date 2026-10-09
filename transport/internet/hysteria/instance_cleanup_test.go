package hysteria

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"os"
	"sync"
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
			c.Lock()
			if c.conn != nil {
				c.close()
			}
			c.Unlock()
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

// exchange proves that conn carries payload to the echo listener and back.
func exchange(t *testing.T, conn stat.Connection, payload string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(cleanupTestDeadline)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatal(err)
	}
	if string(echoed) != payload {
		t.Fatalf("echo returned %q, want %q", echoed, payload)
	}
}

// clientResources are the transport objects of a connected client.
type clientResources struct {
	conn    *quic.Conn
	pktConn xnet.PacketConn
}

func (c *client) resources() clientResources {
	c.Lock()
	defer c.Unlock()
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
				<-dialed
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

			stream, err := m.dialTCP(ctx, dest)
			if err != nil {
				t.Fatal(err)
			}
			exchange(t, stream, "first")
			_ = stream.Close()
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

			stream, err = m.dialTCP(ctx, dest)
			if err != nil {
				t.Fatalf("a reset client did not reconnect: %v", err)
			}
			defer stream.Close()
			exchange(t, stream, "second")
			if second := c.resources().conn; second == nil || second == first {
				t.Fatal("a reset client did not open a new connection")
			}
		})
	}
}

// The cleaner may wait for a client whose dial holds the client lock, for as
// long as a handshake takes. Meanwhile dials through other clients that are
// already in the pool must proceed: the cleaner may hold the pool lock only
// for reading.
func TestCleanerWaitingForOneClientDoesNotBlockOthers(t *testing.T) {
	settings := hysteriaTestSettings(t)
	dest := startEchoListener(t, settings)
	m := newTestClientManager(t, settings)
	ctx := instanceContext(startCleanupTestInstance(t))

	stream, err := m.dialTCP(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	exchange(t, stream, "ready")
	_ = stream.Close()

	slowDest := dest
	slowDest.Network = xnet.Network_UDP
	slowDest.Port++
	slow := &client{}
	m.Lock()
	m.m[dialerConf{slowDest, settings}] = slow
	m.Unlock()

	slow.Lock()
	var unlock sync.Once
	release := func() { unlock.Do(slow.Unlock) }
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
		<-swept
	})

	select {
	case <-reached:
	case <-time.After(cleanupTestDeadline):
		t.Fatal("the cleaner did not reach the stalled client")
	}

	dialed := make(chan error, 1)
	go func() {
		stream, err := m.dialTCP(ctx, dest)
		if err == nil {
			_ = stream.Close()
		}
		dialed <- err
	}()
	select {
	case err := <-dialed:
		if err != nil {
			t.Fatalf("a dial through a ready client failed while the cleaner waited: %v", err)
		}
	case <-time.After(cleanupTestDeadline):
		release()
		<-dialed
		t.Fatal("a dial through a ready client waited for the cleaner")
	}
}
