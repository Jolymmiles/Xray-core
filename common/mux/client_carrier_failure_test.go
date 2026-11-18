package mux_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

// failingCarrier is an outbound whose carrier fails once released, as a
// refused dial or a reset tunnel does: Process returns an error and leaves
// the downlink writer open.
type failingCarrier struct{ release chan struct{} }

func (c failingCarrier) Process(context.Context, *transport.Link, internet.Dialer) error {
	<-c.release
	return errors.New("connection refused")
}

// A session on a dialing worker ends when the worker's carrier fails. Left
// open, its client waits for a reply that cannot come: a SOCKS connection
// that was accepted and then stays silent for as long as the application
// keeps it.
func TestDialingWorkerEndsSessionsWhenCarrierFails(t *testing.T) {
	carrier := failingCarrier{release: make(chan struct{})}
	factory := &mux.DialingWorkerFactory{Proxy: carrier, Strategy: mux.ClientStrategy{MaxConcurrency: 8}}
	worker, err := factory.Create()
	if err != nil {
		t.Fatal(err)
	}
	input, inputWriter := pipe.New(pipe.WithoutSizeLimit())
	defer inputWriter.Close()
	outputReader, output := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.LocalHostIP, 80),
	}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: output}) {
		t.Fatal("worker refused the session")
	}
	close(carrier.release)

	ended := make(chan error, 1)
	go func() {
		_, err := outputReader.ReadMultiBuffer()
		ended <- err
	}()
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("the session's downlink delivered data after its carrier failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("session downlink still open 5s after the carrier failed (worker closed: %t)", worker.Closed())
	}
	select {
	case <-worker.WaitClosed():
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not close after its carrier failed")
	}
	if active := worker.ActiveConnections(); active != 0 {
		t.Fatalf("%d sessions left on a worker whose carrier failed", active)
	}
}
