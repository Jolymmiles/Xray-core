package inbound

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

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
