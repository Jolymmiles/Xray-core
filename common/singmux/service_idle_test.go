// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// newCNCCarrierPair builds the carrier the way production does. Both SMUX entry
// points in common/mux/server.go (dispatchSMUX and DispatchLink) hand
// Service.NewConnection a *cnc.Connection, whose SetDeadline, SetReadDeadline
// and SetWriteDeadline are no-op stubs returning nil. A carrier guard built on
// deadlines compiles, runs, and never fires against this conn.
//
// net.Pipe is not a substitute: it honours deadlines, and it unblocks a parked
// Read through its own close path rather than through cnc's
// done.Close + common.Interrupt.
func newCNCCarrierPair() (clientConn net.Conn, serverConn net.Conn) {
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	serverConn = cnc.NewConnection(
		cnc.ConnectionInputMulti(downlinkWriter),
		cnc.ConnectionOutputMulti(uplinkReader),
	)
	clientConn = cnc.NewConnection(
		cnc.ConnectionInputMulti(uplinkWriter),
		cnc.ConnectionOutputMulti(downlinkReader),
	)
	return clientConn, serverConn
}

// deadlineStubConn keeps net.Pipe's semantics but strips deadline support, so
// the carrier guard cannot lean on SetReadDeadline even accidentally.
type deadlineStubConn struct {
	net.Conn
}

func (*deadlineStubConn) SetDeadline(time.Time) error      { return nil }
func (*deadlineStubConn) SetReadDeadline(time.Time) error  { return nil }
func (*deadlineStubConn) SetWriteDeadline(time.Time) error { return nil }

func newDeadlineStubCarrierPair() (clientConn net.Conn, serverConn net.Conn) {
	client, server := net.Pipe()
	return &deadlineStubConn{Conn: client}, &deadlineStubConn{Conn: server}
}

// startIdleTestCarrier completes the carrier handshake over a caller-supplied
// conn pair and returns the client session plus the NewConnection result.
func startIdleTestCarrier(t *testing.T, service *Service, ctx context.Context, clientConn, serverConn net.Conn) (*localsmux.Session, chan error) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(ctx, serverConn) }()
	if err := writeCarrierRequest(clientConn, protocolSMUX, nil); err != nil {
		_ = clientConn.Close()
		t.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	// Client keepalive would be inbound carrier activity and would mask every
	// assertion in this file.
	config.KeepAliveDisabled = true
	session, err := localsmux.Client(clientConn, config)
	if err != nil {
		_ = clientConn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = clientConn.Close()
	})
	return session, result
}

func awaitCarrierResult(result chan error, within time.Duration) (error, bool) {
	timer := time.NewTimer(within)
	defer timer.Stop()
	select {
	case err := <-result:
		return err, true
	case <-timer.C:
		return nil, false
	}
}

// A carrier that produces no bytes in either direction is unreachable, and SMUX
// wire keepalive is disabled for interop, so nothing else reaps it: the session
// read loop parks in io.ReadFull forever, pinning the connection, both loop
// goroutines and every buffered chunk.
func TestServiceReapsSilentCNCCarrier(t *testing.T) {
	t.Run("reaped", func(t *testing.T) {
		service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
		service.carrierIdleTimeout = 100 * time.Millisecond

		clientConn, serverConn := newCNCCarrierPair()
		_, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)

		err, returned := awaitCarrierResult(result, 5*time.Second)
		if !returned {
			t.Fatal("silent cnc.Connection carrier was never reaped: the idle guard does not work on the only carrier production uses")
		}
		if err == nil {
			t.Fatal("NewConnection reported success for a reaped carrier, want an error")
		}
	})

	// Control: the reap must come from the idle watchdog and from nothing else
	// in this fixture (handshake deadline, pipe EOF, context). Disabled by
	// configuration rather than by neutering production code.
	t.Run("control/pinned without the idle timeout", func(t *testing.T) {
		service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
		service.carrierIdleTimeout = time.Hour

		clientConn, serverConn := newCNCCarrierPair()
		_, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)

		if _, returned := awaitCarrierResult(result, 500*time.Millisecond); returned {
			t.Fatal("carrier returned with the idle timeout an hour away: the reap under test is not the watchdog's doing")
		}
	})
}

// The same guarantee stated as the criterion itself: no Set*Deadline call may
// carry the reap.
func TestServiceReapsSilentCarrierWithStubbedDeadlines(t *testing.T) {
	t.Run("reaped", func(t *testing.T) {
		service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
		service.carrierIdleTimeout = 100 * time.Millisecond

		clientConn, serverConn := newDeadlineStubCarrierPair()
		_, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)

		err, returned := awaitCarrierResult(result, 5*time.Second)
		if !returned {
			t.Fatal("silent carrier with stubbed deadlines was never reaped")
		}
		if err == nil {
			t.Fatal("NewConnection reported success for a reaped carrier, want an error")
		}
	})

	t.Run("control/pinned without the idle timeout", func(t *testing.T) {
		service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
		service.carrierIdleTimeout = time.Hour

		clientConn, serverConn := newDeadlineStubCarrierPair()
		_, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)

		if _, returned := awaitCarrierResult(result, 500*time.Millisecond); returned {
			t.Fatal("carrier returned with the idle timeout an hour away: the reap under test is not the watchdog's doing")
		}
	})
}

// downloadDispatcher models a server->client download: it writes to its link
// forever and never reads. mplsmux acknowledges nothing (frame commands are
// open/close/data/keepalive only), so the carrier carries outbound frames and
// no inbound ones for as long as the transfer runs.
type downloadDispatcher struct {
	started  chan struct{}
	interval time.Duration
}

func (*downloadDispatcher) Dispatch(context.Context, X.Destination) (*transport.Link, error) {
	return nil, io.ErrClosedPipe
}

func (d *downloadDispatcher) DispatchLink(ctx context.Context, _ X.Destination, link *transport.Link) error {
	select {
	case d.started <- struct{}{}:
	default:
	}
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			buffer := buf.New()
			if _, err := buffer.Write([]byte("download")); err != nil {
				buffer.Release()
				return err
			}
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
				return err
			}
		}
	}
}

func (*downloadDispatcher) Start() error      { return nil }
func (*downloadDispatcher) Close() error      { return nil }
func (*downloadDispatcher) Type() interface{} { return routing.DispatcherType() }

// drainStream keeps the download flowing. A client that stops reading would
// stall the server's writes, which would look exactly like an idle carrier and
// invert the assertion below.
func drainStream(t *testing.T, stream *localsmux.Stream) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		payload := make([]byte, 1024)
		for {
			if _, err := stream.Read(payload); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = stream.Close()
		<-done
	})
}

// A download-only carrier is alive, just quiet in the inbound direction. Reaping
// it would break every large server->client transfer, which is a far worse
// outcome than the leak the watchdog exists to close.
func TestServiceKeepsWriteOnlyCarrierAlive(t *testing.T) {
	const idleTimeout = 200 * time.Millisecond

	t.Run("outbound traffic keeps the carrier", func(t *testing.T) {
		dispatcher := &downloadDispatcher{started: make(chan struct{}, 1), interval: 20 * time.Millisecond}
		service := NewService(dispatcher)
		service.streamHandshakeTimeout = time.Second
		service.carrierIdleTimeout = idleTimeout

		clientConn, serverConn := newCNCCarrierPair()
		session, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)
		drainStream(t, openDispatchedStream(t, session, dispatcher.started))

		if _, returned := awaitCarrierResult(result, 5*idleTimeout); returned {
			t.Fatal("a carrier carrying a live download was reaped: activity is tracked on reads only")
		}
	})

	// Control: identical inbound traffic (one stream open plus its handshake),
	// no outbound traffic. This one must be reaped, which is what makes the
	// assertion above a statement about Write tracking and not about the
	// watchdog being asleep.
	t.Run("control/no outbound traffic is reaped", func(t *testing.T) {
		dispatcher := &detachedDispatcher{started: make(chan struct{}, 1)}
		service := NewService(dispatcher)
		service.streamHandshakeTimeout = time.Second
		service.carrierIdleTimeout = idleTimeout

		clientConn, serverConn := newCNCCarrierPair()
		session, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)
		openDispatchedStream(t, session, dispatcher.started)

		if _, returned := awaitCarrierResult(result, 5*time.Second); !returned {
			t.Fatal("a carrier with an open but completely silent stream was never reaped")
		}
	})
}

// D24. The carrier handshake read is bounded by SetReadDeadline, which a
// cnc.Connection ignores, so a peer that connects and then says nothing parks
// readCarrierRequest forever — before any session exists for the idle watchdog
// or anything else to reap.
//
// This and its sibling below land at almost exactly 0.60s =
// carrierHandshakeTimeout 100ms + handshakeWatchdogGrace 500ms, which is what
// makes them evidence: nothing else in either fixture ends at that time, so the
// watchdog is provably what reaped the carrier.
func TestServiceBoundsCarrierHandshakeOnStubbedDeadlines(t *testing.T) {
	service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
	service.carrierHandshakeTimeout = 100 * time.Millisecond

	// No writeCarrierRequest: the peer connects and stays silent.
	clientConn, serverConn := newCNCCarrierPair()
	defer clientConn.Close()
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(context.Background(), serverConn) }()

	if _, returned := awaitCarrierResult(result, 5*time.Second); !returned {
		t.Fatal("a carrier that never sent its handshake was never reaped")
	}
}

// D29. The handshake bound must not be hung off the idle watchdog: a Service
// whose carrierIdleTimeout is zero switches the watchdog off, and that must not
// silently take the handshake bound with it.
func TestServiceBoundsCarrierHandshakeWithoutIdleWatchdog(t *testing.T) {
	service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
	service.carrierHandshakeTimeout = 100 * time.Millisecond
	service.carrierIdleTimeout = 0

	clientConn, serverConn := newCNCCarrierPair()
	defer clientConn.Close()
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(context.Background(), serverConn) }()

	if _, returned := awaitCarrierResult(result, 5*time.Second); !returned {
		t.Fatal("zeroing carrierIdleTimeout removed the handshake bound as well")
	}
}

// idlePolicyManager reports one connIdle for every level, which is all the
// derivation reads.
type idlePolicyManager struct {
	policy.Manager
	connectionIdle time.Duration
}

func (m *idlePolicyManager) ForLevel(uint32) policy.Session {
	session := policy.SessionDefault()
	session.Timeouts.ConnectionIdle = m.connectionIdle
	return session
}

// D31/D33. Reaping is safe only while the carrier window is at least the
// effective connIdle, and connIdle is operator-settable with no clamp, so the
// constant cannot be trusted to hold that on its own — it has to be derived.
func TestServiceDerivesCarrierIdleTimeoutFromPolicy(t *testing.T) {
	cases := []struct {
		name           string
		connectionIdle time.Duration
		configured     time.Duration
		want           time.Duration
	}{
		{
			name:           "policy above the configured window raises it",
			connectionIdle: 30 * time.Minute,
			configured:     defaultCarrierIdleTimeout,
			want:           time.Hour,
		},
		{
			// The level-1 default: equal windows already leave no margin, so the
			// derivation has to move even here.
			name:           "policy equal to the configured window raises it",
			connectionIdle: 10 * time.Minute,
			configured:     defaultCarrierIdleTimeout,
			want:           20 * time.Minute,
		},
		{
			name:           "policy below the configured window leaves it alone",
			connectionIdle: time.Minute,
			configured:     defaultCarrierIdleTimeout,
			want:           defaultCarrierIdleTimeout,
		},
		{
			// Derivation raises a timeout, it never enables one.
			name:           "a disabled watchdog stays disabled",
			connectionIdle: time.Hour,
			configured:     0,
			want:           0,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
			service.carrierIdleTimeout = testCase.configured
			service.SetPolicy(&idlePolicyManager{connectionIdle: testCase.connectionIdle})

			if got := service.carrierIdleTimeoutFor(context.Background()); got != testCase.want {
				t.Fatalf("carrierIdleTimeoutFor = %v, want %v", got, testCase.want)
			}
		})
	}

	// Without a policy manager the configured value stands: SetPolicy is
	// optional, and every test in this package relies on that.
	t.Run("no policy manager leaves the configured value", func(t *testing.T) {
		service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
		if got := service.carrierIdleTimeoutFor(context.Background()); got != defaultCarrierIdleTimeout {
			t.Fatalf("carrierIdleTimeoutFor = %v, want %v", got, defaultCarrierIdleTimeout)
		}
	})
}

// The derivation reads the level of the carrier's own inbound user, because
// every stream the carrier multiplexes belongs to that user.
func TestServiceDerivesCarrierIdleTimeoutForInboundUserLevel(t *testing.T) {
	service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
	service.SetPolicy(&levelPolicyManager{})

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		User: &protocol.MemoryUser{Level: 7},
	})
	if got := service.carrierIdleTimeoutFor(ctx); got != 2*time.Hour {
		t.Fatalf("carrierIdleTimeoutFor at level 7 = %v, want %v", got, 2*time.Hour)
	}
	// Anonymous inbounds fall back to level 0.
	if got := service.carrierIdleTimeoutFor(context.Background()); got != defaultCarrierIdleTimeout {
		t.Fatalf("carrierIdleTimeoutFor without a user = %v, want %v", got, defaultCarrierIdleTimeout)
	}
}

// levelPolicyManager gives level 7 a connIdle far above the default and every
// other level a negligible one, so a derivation that ignored the level would
// read the wrong window.
type levelPolicyManager struct {
	policy.Manager
}

func (*levelPolicyManager) ForLevel(level uint32) policy.Session {
	result := policy.SessionDefault()
	result.Timeouts.ConnectionIdle = time.Second
	if level == 7 {
		result.Timeouts.ConnectionIdle = time.Hour
	}
	return result
}

// The watchdog must be joined, not merely signalled. An hour-long idle timeout
// parks it: if NewConnection returns without waiting for it, the goroutine
// survives the whole hour and shows up in a settled count.
func TestServiceJoinsIdleWatchdogBeforeReturn(t *testing.T) {
	baseline := settledGoroutines()
	const carriers = 8
	for range carriers {
		service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
		service.carrierIdleTimeout = time.Hour

		clientConn, serverConn := newCNCCarrierPair()
		_, result := startIdleTestCarrier(t, service, context.Background(), clientConn, serverConn)
		// The peer vanishes, so NewConnection returns while the idle timer is
		// still an hour from firing.
		_ = clientConn.Close()
		if _, returned := awaitCarrierResult(result, 5*time.Second); !returned {
			t.Fatal("NewConnection did not return after the peer closed the carrier")
		}
	}
	if leaked := settledGoroutines() - baseline; leaked > 2 {
		t.Fatalf("goroutine count grew by %d over %d carriers: the idle watchdog outlives NewConnection", leaked, carriers)
	}
}
