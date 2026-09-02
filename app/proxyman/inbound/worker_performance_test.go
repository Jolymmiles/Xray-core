package inbound

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singmux"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestReceiverH2MuxOptions(t *testing.T) {
	tests := []struct {
		name   string
		config *proxyman.ReceiverConfig
		want   singmux.H2MuxOptions
	}{
		{name: "nil receiver"},
		{name: "nil smux", config: &proxyman.ReceiverConfig{}},
		{
			name:   "omitted frame size",
			config: &proxyman.ReceiverConfig{SmuxSettings: &proxyman.SmuxConfig{}},
		},
		{
			name: "configured frame size",
			config: &proxyman.ReceiverConfig{SmuxSettings: &proxyman.SmuxConfig{
				H2MuxMaxReadFrameSize: 16384,
			}},
			want: singmux.H2MuxOptions{MaxReadFrameSize: 16384},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := receiverH2MuxOptions(test.config); got != test.want {
				t.Fatalf("receiverH2MuxOptions() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestReceiverBrutalOptions(t *testing.T) {
	tests := []struct {
		name   string
		config *proxyman.ReceiverConfig
		want   singmux.BrutalOptions
	}{
		{name: "nil receiver"},
		{name: "nil smux", config: &proxyman.ReceiverConfig{}},
		{
			name: "configured",
			config: &proxyman.ReceiverConfig{SmuxSettings: &proxyman.SmuxConfig{
				Brutal: &proxyman.BrutalConfig{Enabled: true, UpBps: 7, DownBps: 9},
			}},
			want: singmux.BrutalOptions{Enabled: true, SendBPS: 7, ReceiveBPS: 9},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := receiverBrutalOptions(test.config); got != test.want {
				t.Fatalf("receiverBrutalOptions() = %#v, want %#v", got, test.want)
			}
		})
	}
}

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

type contextCapturingInbound struct {
	done <-chan struct{}
}

func (*contextCapturingInbound) Network() []net.Network { return []net.Network{net.Network_TCP} }

func (p *contextCapturingInbound) Process(ctx context.Context, _ net.Network, _ stat.Connection, _ routing.Dispatcher) error {
	p.done = ctx.Done()
	return nil
}

type childCancelInbound struct{}

func (*childCancelInbound) Network() []net.Network { return []net.Network{net.Network_TCP} }

func (*childCancelInbound) Process(ctx context.Context, _ net.Network, _ stat.Connection, _ routing.Dispatcher) error {
	child, cancel := context.WithCancel(ctx)
	cancel()
	<-child.Done()
	return nil
}

type inertConnection struct{}

var (
	inertLocalAddress  = &stdnet.TCPAddr{IP: stdnet.IP{127, 0, 0, 1}, Port: 1}
	inertRemoteAddress = &stdnet.TCPAddr{IP: stdnet.IP{127, 0, 0, 1}, Port: 2}
)

func (*inertConnection) Read([]byte) (int, error)          { return 0, io.EOF }
func (*inertConnection) Write(payload []byte) (int, error) { return len(payload), nil }
func (*inertConnection) Close() error                      { return nil }
func (*inertConnection) LocalAddr() stdnet.Addr            { return inertLocalAddress }
func (*inertConnection) RemoteAddr() stdnet.Addr           { return inertRemoteAddress }
func (*inertConnection) SetDeadline(time.Time) error       { return nil }
func (*inertConnection) SetReadDeadline(time.Time) error   { return nil }
func (*inertConnection) SetWriteDeadline(time.Time) error  { return nil }

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

func BenchmarkTCPWorkerWithChildCancelContext(b *testing.B) {
	worker := &tcpWorker{ctx: context.Background(), proxy: new(childCancelInbound)}
	connection := new(inertConnection)

	b.ReportAllocs()
	for b.Loop() {
		worker.handleConnection(connection)
	}
}

func TestTCPWorkerAcceptedConnectionAllocationBudget(t *testing.T) {
	proxy := &benchmarkInbound{processed: make(chan struct{}, 1)}
	worker := &tcpWorker{ctx: context.Background(), proxy: proxy}
	connection := new(inertConnection)
	allocations := testing.AllocsPerRun(1000, func() {
		worker.handleConnection(connection)
		<-proxy.processed
	})
	if allocations > 11 {
		t.Fatalf("TCP accepted connection allocations = %.0f, want at most 11", allocations)
	}
}

func TestTCPWorkerClosesContextDoneAfterProcessReturns(t *testing.T) {
	proxy := new(contextCapturingInbound)
	worker := &tcpWorker{ctx: context.Background(), proxy: proxy}
	worker.handleConnection(new(inertConnection))

	if proxy.done == nil {
		t.Fatal("inbound context has no Done channel")
	}
	select {
	case <-proxy.done:
	default:
		t.Fatal("context Done remains open after connection processing")
	}
}
