package inbound

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"testing/synctest"
	"time"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestUDPWorkerCloseAllowsAdmittedCleanupToFinish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		worker := &udpWorker{activeConn: map[connID]*udpConn{
			{}: {lastActivityTime: time.Now().Unix()},
		}}
		continueCleanup := make(chan struct{})
		cleanupResult := make(chan error, 1)
		worker.checker = &task.Periodic{
			Interval: time.Hour,
			Execute: func() error {
				<-continueCleanup
				// Detect the lock inversion without leaving a permanently blocked
				// cleanup goroutine on the failing implementation.
				if !worker.TryLock() {
					return fmt.Errorf("shutdown holds the mutex required by cleanup")
				}
				worker.Unlock()
				return worker.clean()
			},
		}
		go func() { cleanupResult <- worker.checker.Start() }()
		synctest.Wait()
		closeResult := make(chan error, 1)
		go func() { closeResult <- worker.Close() }()
		synctest.Wait()
		select {
		case <-closeResult:
			t.Fatal("shutdown returned before admitted cleanup finished")
		default:
		}
		close(continueCleanup)
		if err := <-cleanupResult; err != nil {
			t.Error(err)
		}
		if err := <-closeResult; err != nil {
			t.Fatal(err)
		}
	})
}

type escapedContextResult struct {
	id         c.ID
	inboundTag string
	doneClosed bool
	err        error
}

type contextEscapingInbound struct {
	useContext chan struct{}
	result     chan escapedContextResult
	expectedID c.ID
}

func (*contextEscapingInbound) Network() []net.Network { return []net.Network{net.Network_TCP} }

func (p *contextEscapingInbound) Process(ctx context.Context, _ net.Network, _ stat.Connection, _ routing.Dispatcher) error {
	p.expectedID = c.IDFromContext(ctx)
	go func() {
		<-p.useContext
		result := escapedContextResult{}
		defer func() {
			if recovered := recover(); recovered != nil {
				result.err = fmt.Errorf("panic while using escaped inbound context: %v", recovered)
			}
			p.result <- result
		}()
		result.id = c.IDFromContext(ctx)
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			result.inboundTag = inbound.Tag
		}
		select {
		case <-ctx.Done():
			result.doneClosed = true
		default:
		}
	}()
	return nil
}

type lifecycleConnection struct{}

func (*lifecycleConnection) Read([]byte) (int, error)          { return 0, io.EOF }
func (*lifecycleConnection) Write(payload []byte) (int, error) { return len(payload), nil }
func (*lifecycleConnection) Close() error                      { return nil }
func (*lifecycleConnection) LocalAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 1}
}

func (*lifecycleConnection) RemoteAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 2}
}
func (*lifecycleConnection) SetDeadline(time.Time) error      { return nil }
func (*lifecycleConnection) SetReadDeadline(time.Time) error  { return nil }
func (*lifecycleConnection) SetWriteDeadline(time.Time) error { return nil }

func TestTCPWorkerContextRemainsUsableByAsyncChildAfterProcessReturns(t *testing.T) {
	proxy := &contextEscapingInbound{
		useContext: make(chan struct{}),
		result:     make(chan escapedContextResult, 1),
	}
	worker := &tcpWorker{ctx: context.Background(), proxy: proxy, tag: "vless-in"}
	worker.handleConnection(new(lifecycleConnection))

	close(proxy.useContext)
	select {
	case result := <-proxy.result:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.id != proxy.expectedID {
			t.Fatalf("escaped session ID = %d, want %d", result.id, proxy.expectedID)
		}
		if result.inboundTag != "vless-in" {
			t.Fatalf("escaped inbound tag = %q, want vless-in", result.inboundTag)
		}
		if !result.doneClosed {
			t.Fatal("escaped context was not cancelled after connection processing")
		}
	case <-time.After(time.Second):
		t.Fatal("async inbound child did not finish")
	}
}
