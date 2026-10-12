package inbound

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const closeWait = 5 * time.Second

// readingInbound serves each connection like a copy loop that ignores its
// context: it reads until a read fails, which only closing the connection
// causes.
type readingInbound struct {
	started chan struct{}
	ended   chan error
}

func newReadingInbound() *readingInbound {
	return &readingInbound{started: make(chan struct{}, 8), ended: make(chan error, 8)}
}

func (*readingInbound) Network() []net.Network { return []net.Network{net.Network_TCP} }

func (p *readingInbound) Process(_ context.Context, _ net.Network, conn stat.Connection, _ routing.Dispatcher) error {
	p.started <- struct{}{}
	var err error
	if reader, ok := conn.(buf.Reader); ok {
		for err == nil {
			var mb buf.MultiBuffer
			mb, err = reader.ReadMultiBuffer()
			buf.ReleaseMulti(mb)
		}
	} else {
		_, err = io.Copy(io.Discard, conn)
		if err == nil {
			err = io.EOF
		}
	}
	p.ended <- err
	return err
}

// contextInbound serves each connection until its context ends, like an
// outbound waiting on a dial or a transport only the context interrupts.
type contextInbound struct {
	started chan struct{}
	ended   chan struct{}
}

func (*contextInbound) Network() []net.Network { return []net.Network{net.Network_TCP} }

func (p *contextInbound) Process(ctx context.Context, _ net.Network, _ stat.Connection, _ routing.Dispatcher) error {
	p.started <- struct{}{}
	<-ctx.Done()
	p.ended <- struct{}{}
	return ctx.Err()
}

func receiveWithin(t *testing.T, channel <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(closeWait):
		t.Fatal(what)
	}
}

// loopbackPair returns the accepted and the dialed end of a TCP connection.
func loopbackPair(t *testing.T) (stdnet.Conn, stdnet.Conn) {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := stdnet.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return server, client
}

func requirePeerSeesEnd(t *testing.T, peer stdnet.Conn, name string) {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(closeWait)); err != nil {
		t.Fatal(err)
	}
	_, err := io.Copy(io.Discard, peer)
	var netErr stdnet.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("%s: the connection is still open %v after the worker closed", name, closeWait)
	}
}

// connectionWorker is the common shape of the TCP and Unix socket workers.
type connectionWorker struct {
	serve  func(stat.Connection)
	close  func() error
	setHub func(internet.Listener)
	// stop ends the worker's parent context, so a test that fails still
	// releases a Process that waits on it.
	stop context.CancelFunc
}

var connectionWorkerKinds = []string{"tcp", "unix"}

func newConnectionWorker(kind string, proxy interface {
	Network() []net.Network
	Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error
},
) connectionWorker {
	ctx, stop := context.WithCancel(context.Background())
	if kind == "tcp" {
		w := &tcpWorker{ctx: ctx, proxy: proxy, tag: "removed-in"}
		return connectionWorker{serve: w.handleConnection, close: w.Close, setHub: func(h internet.Listener) { w.hub = h }, stop: stop}
	}
	w := &dsWorker{ctx: ctx, proxy: proxy, tag: "removed-in", address: net.DomainAddress("/tmp/removed-in.sock")}
	return connectionWorker{serve: w.callback, close: w.Close, setHub: func(h internet.Listener) { w.hub = h }, stop: stop}
}

// serveInBackground serves conn with worker in a goroutine and returns a
// channel closed once it is done. Cleanup stops the worker's context and
// joins the goroutine.
func serveInBackground(t *testing.T, worker connectionWorker, conn stat.Connection, done func()) <-chan struct{} {
	t.Helper()
	served := make(chan struct{})
	go func() {
		defer close(served)
		if done != nil {
			defer done()
		}
		worker.serve(conn)
	}()
	t.Cleanup(func() {
		worker.stop()
		conn.Close()
		select {
		case <-served:
		case <-time.After(closeWait):
			t.Error("the worker goroutine did not return")
		}
	})
	return served
}

func TestWorkerCloseClosesLiveConnections(t *testing.T) {
	for _, kind := range connectionWorkerKinds {
		t.Run(kind, func(t *testing.T) {
			proxy := newReadingInbound()
			worker := newConnectionWorker(kind, proxy)
			server, client := loopbackPair(t)
			served := serveInBackground(t, worker, server, nil)
			receiveWithin(t, proxy.started, "Process did not start")

			if err := worker.close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-proxy.ended:
			case <-time.After(closeWait):
				t.Fatalf("Process still reads its connection %v after the worker closed", closeWait)
			}
			receiveWithin(t, served, "the worker did not finish the connection")
			requirePeerSeesEnd(t, client, kind)
		})
	}
}

func TestWorkerCloseCancelsLiveConnections(t *testing.T) {
	for _, kind := range connectionWorkerKinds {
		t.Run(kind, func(t *testing.T) {
			proxy := &contextInbound{started: make(chan struct{}, 1), ended: make(chan struct{}, 1)}
			worker := newConnectionWorker(kind, proxy)
			server, _ := loopbackPair(t)
			served := serveInBackground(t, worker, server, nil)
			receiveWithin(t, proxy.started, "Process did not start")

			if err := worker.close(); err != nil {
				t.Fatal(err)
			}
			receiveWithin(t, proxy.ended, "the context of a live connection was not canceled when the worker closed")
			receiveWithin(t, served, "the worker did not finish the connection")
		})
	}
}

func TestWorkerRefusesConnectionsAfterClose(t *testing.T) {
	for _, kind := range connectionWorkerKinds {
		t.Run(kind, func(t *testing.T) {
			proxy := newReadingInbound()
			worker := newConnectionWorker(kind, proxy)
			if err := worker.close(); err != nil {
				t.Fatal(err)
			}
			server, client := loopbackPair(t)
			served := serveInBackground(t, worker, server, nil)
			receiveWithin(t, served, "a closed worker kept serving a late connection")
			select {
			case <-proxy.started:
				t.Fatal("a closed worker passed a late connection to Process")
			default:
			}
			requirePeerSeesEnd(t, client, kind)
		})
	}
}

// waitingHub is a listener whose Close waits for the handlers it started, as
// the Hysteria and XHTTP over HTTP/3 hubs do.
type waitingHub struct {
	handlers sync.WaitGroup
}

func (*waitingHub) Addr() stdnet.Addr { return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)} }

func (h *waitingHub) Close() error {
	h.handlers.Wait()
	return nil
}

func TestWorkerCloseEndsConnectionsBeforeWaitingForItsHub(t *testing.T) {
	for _, kind := range connectionWorkerKinds {
		t.Run(kind, func(t *testing.T) {
			proxy := &contextInbound{started: make(chan struct{}, 1), ended: make(chan struct{}, 1)}
			worker := newConnectionWorker(kind, proxy)
			hub := &waitingHub{}
			worker.setHub(hub)
			closed := make(chan error, 1)
			// Join the Close below last, once cleanup has released the handler.
			t.Cleanup(func() {
				select {
				case <-closed:
				case <-time.After(closeWait):
					t.Error("the worker's Close did not return")
				}
			})
			server, _ := loopbackPair(t)
			hub.handlers.Add(1)
			serveInBackground(t, worker, server, hub.handlers.Done)
			receiveWithin(t, proxy.started, "Process did not start")

			go func() { closed <- worker.close() }()
			select {
			case err := <-closed:
				closed <- err
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(closeWait):
				t.Fatal("the worker waited for its hub before ending the connections the hub waits for")
			}
		})
	}
}

func newUDPTestWorker(t *testing.T, proxy *readingInbound) *udpWorker {
	t.Helper()
	worker := &udpWorker{
		proxy:   proxy,
		address: net.LocalHostIP,
		port:    0,
		tag:     "removed-in",
		stream:  &internet.MemoryStreamConfig{},
		ctx:     context.WithValue(context.Background(), "cone", true),
	}
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	return worker
}

func sendUDP(t *testing.T, worker *udpWorker) {
	t.Helper()
	client, err := stdnet.DialUDP("udp", nil, worker.hub.Addr().(*stdnet.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
}

func TestUDPWorkerCloseEndsLiveSessions(t *testing.T) {
	proxy := newReadingInbound()
	worker := newUDPTestWorker(t, proxy)
	sendUDP(t, worker)
	receiveWithin(t, proxy.started, "the UDP session did not start")

	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proxy.ended:
	case <-time.After(closeWait):
		t.Fatalf("a UDP session still runs %v after the worker closed", closeWait)
	}
}

func TestUDPWorkerOpensNoSessionAfterClose(t *testing.T) {
	proxy := newReadingInbound()
	worker := newUDPTestWorker(t, proxy)
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}

	// A datagram the hub delivered before it closed reaches the callback
	// late.
	payload := buf.New()
	payload.WriteString("late")
	source := net.UDPDestination(net.LocalHostIP, 40000)
	worker.callback(payload, source, net.Destination{}, source)

	worker.RLock()
	defer worker.RUnlock()
	if len(worker.activeConn) != 0 {
		t.Fatalf("a closed UDP worker holds %d sessions", len(worker.activeConn))
	}
}

func TestUDPWorkerKeepsANewerSessionOfTheSameSource(t *testing.T) {
	worker := &udpWorker{activeConn: make(map[connID]*udpConn)}
	id := connID{src: net.UDPDestination(net.LocalHostIP, 40000)}
	ended := &udpConn{}
	newer := &udpConn{}
	// The ended session's goroutine runs after a datagram from the same
	// source opened a newer session under its ID.
	worker.activeConn[id] = newer
	worker.removeConn(id, ended)
	if worker.activeConn[id] != newer {
		t.Fatal("removing an ended session removed the newer session of the same source")
	}
}
