package inbound

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type blockingInbound struct {
	started chan struct{}
	release chan struct{}
}

func (*blockingInbound) Network() []net.Network { return []net.Network{net.Network_TCP} }

func (p *blockingInbound) Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
	close(p.started)
	<-p.release
	return nil
}

type benchmarkInbound struct {
	processed chan struct{}
}

func (*benchmarkInbound) Network() []net.Network { return []net.Network{net.Network_TCP} }

func (p *benchmarkInbound) Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
	p.processed <- struct{}{}
	return nil
}

type inertConnection struct{}

func (*inertConnection) Read([]byte) (int, error)          { return 0, io.EOF }
func (*inertConnection) Write(payload []byte) (int, error) { return len(payload), nil }
func (*inertConnection) Close() error                      { return nil }
func (*inertConnection) LocalAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 1}
}
func (*inertConnection) RemoteAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 2}
}
func (*inertConnection) SetDeadline(time.Time) error      { return nil }
func (*inertConnection) SetReadDeadline(time.Time) error  { return nil }
func (*inertConnection) SetWriteDeadline(time.Time) error { return nil }

func TestTCPWorkerHandlesAcceptedConnectionInline(t *testing.T) {
	proxy := &blockingInbound{started: make(chan struct{}), release: make(chan struct{})}
	worker := &tcpWorker{ctx: context.Background(), proxy: proxy}
	done := make(chan struct{})
	go func() {
		worker.handleConnection(new(inertConnection))
		close(done)
	}()

	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("inbound processing did not start")
	}
	select {
	case <-done:
		t.Fatal("connection handler returned before inbound processing completed")
	default:
	}
	close(proxy.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not return after inbound processing completed")
	}
}

func BenchmarkTCPWorkerAcceptedConnection(b *testing.B) {
	proxy := &benchmarkInbound{processed: make(chan struct{}, 1)}
	worker := &tcpWorker{ctx: context.Background(), proxy: proxy}
	connection := new(inertConnection)

	b.ReportAllocs()
	for b.Loop() {
		worker.handleConnection(connection)
		<-proxy.processed
	}
}
