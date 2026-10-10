package outbound

import (
	"context"
	"io"
	stdnet "net"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// preconnectDialer hands every pre-connect dial to the test: it reports the
// call on entered and returns what the test sends on results. Once the test
// sets closed, a dial that starts is one the closed handler should not have
// made: it is counted and its goroutine ends, so that an implementation that
// keeps redialing cannot spin in the bubble.
type preconnectDialer struct {
	entered    chan struct{}
	results    chan preconnectResult
	closed     atomic.Bool
	afterClose atomic.Int32
}

type preconnectResult struct {
	conn stat.Connection
	err  error
}

func newPreconnectDialer() *preconnectDialer {
	return &preconnectDialer{entered: make(chan struct{}), results: make(chan preconnectResult)}
}

func (d *preconnectDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	if d.closed.Load() {
		d.afterClose.Add(1)
		runtime.Goexit()
	}
	d.entered <- struct{}{}
	result := <-d.results
	return result.conn, result.err
}

func (*preconnectDialer) DestIpAddress() net.IP { return nil }

func (*preconnectDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

// preconnectConn fails every read and write, so a request that takes it ends
// at once, and counts its closes.
type preconnectConn struct {
	closes atomic.Int32
}

func (*preconnectConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*preconnectConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *preconnectConn) Close() error                   { c.closes.Add(1); return nil }
func (*preconnectConn) LocalAddr() stdnet.Addr           { return &stdnet.TCPAddr{} }
func (*preconnectConn) RemoteAddr() stdnet.Addr          { return &stdnet.TCPAddr{} }
func (*preconnectConn) SetDeadline(time.Time) error      { return nil }
func (*preconnectConn) SetReadDeadline(time.Time) error  { return nil }
func (*preconnectConn) SetWriteDeadline(time.Time) error { return nil }

type discardLogHandler struct{}

func (discardLogHandler) Handle(log.Message) {}

// newTestpreInstance also replaces the stdout logger for the test: its writer
// goroutine, started by the first message logged in a bubble, would join the
// bubble and never block durably.
func newTestpreInstance(t *testing.T) *core.Instance {
	t.Helper()
	log.RegisterHandler(discardLogHandler{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// newTestpreHandler builds the handler inside the bubble, so that the
// channels and contexts it creates belong to it.
func newTestpreHandler(t *testing.T, v *core.Instance) *Handler {
	t.Helper()
	ctx := context.WithValue(context.Background(), core.XrayKey(1), v)
	ctx = context.WithValue(ctx, "cone", true)
	id := uuid.New()
	h, err := New(ctx, &Config{Vnext: &protocol.ServerEndpoint{
		Address: net.NewIPOrDomain(net.LocalHostIP),
		Port:    443,
		User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{
			Id:      id.String(),
			Testpre: 1,
		})},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testpreRequest(ctx context.Context, h *Handler, dialer *preconnectDialer) chan error {
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}})
	processed := make(chan error, 1)
	go func() { processed <- h.Process(ctx, &transport.Link{}, dialer) }()
	return processed
}

// RemoveOutbound closes a handler at runtime, while a request may wait for a
// pre-connection: Close must end that wait, a second Close must not panic,
// and a pre-connect whose dial fails afterwards must stop instead of
// redialing.
func TestTestpreCloseStopsFailingPreConnect(t *testing.T) {
	v := newTestpreInstance(t)
	synctest.Test(t, func(t *testing.T) {
		h := newTestpreHandler(t, v)
		dialer := newPreconnectDialer()
		processed := testpreRequest(context.Background(), h, dialer)
		<-dialer.entered

		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("a second Close panicked: %v", recovered)
				}
			}()
			if err := h.Close(); err != nil {
				t.Errorf("a second Close: %v", err)
			}
		}()
		dialer.closed.Store(true)
		dialer.results <- preconnectResult{err: errors.New("connection refused")}
		if err := <-processed; err == nil {
			t.Error("a request waiting for a pre-connection got no error when the handler closed")
		}
		synctest.Wait()
		if n := dialer.afterClose.Load(); n != 0 {
			t.Errorf("the closed handler's pre-connect dialed again after a failed dial (%d dials)", n)
		}
	})
}

// A pre-connect that was dialing when the handler closed has nobody to hand
// its connection to: it must close it.
func TestTestpreClosesConnectionDialedAcrossClose(t *testing.T) {
	v := newTestpreInstance(t)
	synctest.Test(t, func(t *testing.T) {
		h := newTestpreHandler(t, v)
		dialer := newPreconnectDialer()
		processed := testpreRequest(context.Background(), h, dialer)
		<-dialer.entered

		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-processed; err == nil {
			t.Error("a request waiting for a pre-connection got no error when the handler closed")
		}
		dialer.closed.Store(true)
		conn := &preconnectConn{}
		dialer.results <- preconnectResult{conn: conn}
		synctest.Wait()
		if n := conn.closes.Load(); n != 1 {
			t.Errorf("the connection a pre-connect dialed across Close was closed %d times, want 1", n)
		}
		if n := dialer.afterClose.Load(); n != 0 {
			t.Errorf("the closed handler's pre-connect dialed again (%d dials)", n)
		}
	})
}

// The pre-connect waits between handing a connection over and its next dial;
// Close must end that wait instead of letting it dial once more.
func TestTestpreCloseEndsWaitBeforeNextDial(t *testing.T) {
	v := newTestpreInstance(t)
	synctest.Test(t, func(t *testing.T) {
		h := newTestpreHandler(t, v)
		dialer := newPreconnectDialer()
		processed := testpreRequest(context.Background(), h, dialer)
		<-dialer.entered
		conn := &preconnectConn{}
		dialer.results <- preconnectResult{conn: conn}
		if err := <-processed; err == nil {
			t.Error("a request over a failing pre-connection returned no error")
		}
		synctest.Wait()
		if n := conn.closes.Load(); n != 1 {
			t.Errorf("the request closed its pre-connection %d times, want 1", n)
		}

		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		dialer.closed.Store(true)
		// Advance the bubble's clock past any wait Close left running.
		time.Sleep(time.Second)
		synctest.Wait()
		if n := dialer.afterClose.Load(); n != 0 {
			t.Errorf("the closed handler's pre-connect dialed again after its wait (%d dials)", n)
		}
	})
}

// A handler can be selected just before RemoveOutbound unpublishes it, so a
// request may reach Process after Close. It must fail at once and start no
// pre-connect.
func TestTestpreProcessAfterCloseDoesNotDial(t *testing.T) {
	v := newTestpreInstance(t)
	synctest.Test(t, func(t *testing.T) {
		h := newTestpreHandler(t, v)
		dialer := newPreconnectDialer()
		dialer.closed.Store(true)
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		processed := testpreRequest(context.Background(), h, dialer)
		synctest.Wait()
		select {
		case err := <-processed:
			if err == nil {
				t.Error("Process on a closed handler returned no error")
			}
		default:
			t.Error("Process on a closed handler waited for a pre-connection")
			// Where Close closes the channel, closing again releases it.
			_ = h.Close()
			<-processed
		}
		synctest.Wait()
		if n := dialer.afterClose.Load(); n != 0 {
			t.Errorf("Process on a closed handler started a pre-connect that dialed %d times", n)
		}
	})
}

// A request whose context ends while it waits for a pre-connection must stop
// waiting; the shared pre-connects keep running until Close.
func TestTestpreRequestCancelEndsWait(t *testing.T) {
	v := newTestpreInstance(t)
	synctest.Test(t, func(t *testing.T) {
		h := newTestpreHandler(t, v)
		dialer := newPreconnectDialer()
		ctx, cancel := context.WithCancel(context.Background())
		processed := testpreRequest(ctx, h, dialer)
		<-dialer.entered
		cancel()
		synctest.Wait()
		returned := false
		select {
		case err := <-processed:
			returned = true
			if err == nil {
				t.Error("a canceled request returned no error")
			}
		default:
			t.Error("a canceled request kept waiting for a pre-connection")
		}

		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		dialer.closed.Store(true)
		dialer.results <- preconnectResult{err: errors.New("connection refused")}
		if !returned {
			<-processed
		}
		synctest.Wait()
	})
}
