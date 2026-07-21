package mux_test

import (
	"context"
	"fmt"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type noopDispatcher struct{}

func (noopDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, fmt.Errorf("unexpected Dispatch")
}

func (noopDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

func (noopDispatcher) Start() error      { return nil }
func (noopDispatcher) Close() error      { return nil }
func (noopDispatcher) Type() interface{} { return routing.DispatcherType() }

// TestServerWorkerDoneMeansLinkIsFullyReleased is the root-cause regression:
//
// After mux #5110, done was closed when run() exited, while monitor still
// Interrupted link.Reader afterward. VLESS Process waits on done (DispatchLink),
// then defer-Releases a pooled BufferedReader that is still link.Reader →
// use-after-pool / SIGSEGV.
//
// Contract: WaitClosed/done only after finish() has Interrupted the link.
// Callers may then Release pooled readers without racing the worker.
func TestServerWorkerDoneMeansLinkIsFullyReleased(t *testing.T) {
	const iterations = 1000

	for i := 0; i < iterations; i++ {
		server, client := stdnet.Pipe()
		// proxy/vless/inbound.Process body reader construction
		pooled := buf.NewPooledBufferedReader(buf.NewPooledReader(server), nil)
		link := &transport.Link{
			Reader: pooled,
			Writer: buf.Discard,
		}

		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
		worker, err := mux.NewServerWorker(ctx, noopDispatcher{}, link)
		if err != nil {
			t.Fatal(err)
		}

		_ = client.Close()
		_ = server.Close()
		<-worker.WaitClosed()

		// VLESS: DispatchLink returned → defer reader.Release()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("iter %d: Release after WaitClosed panicked: %v", i, r)
				}
			}()
			pooled.Release()
		}()
	}

	time.Sleep(20 * time.Millisecond)
}

// TestClientWorkerDoneMeansLinkIsFullyReleased covers the reverse-mux path
// (VLESS NewMux waits on ClientWorker.WaitClosed, then Process Releases).
func TestClientWorkerDoneMeansLinkIsFullyReleased(t *testing.T) {
	const iterations = 1000

	for i := 0; i < iterations; i++ {
		opt := pipe.WithoutSizeLimit()
		upReader, upWriter := pipe.New(opt)
		_, downWriter := pipe.New(opt)

		workerLink := transport.Link{Reader: upReader, Writer: downWriter}
		client, err := mux.NewClientWorker(workerLink, mux.ClientStrategy{})
		if err != nil {
			t.Fatal(err)
		}

		// Close uplink writer so ClientWorker.fetchOutput hits EOF and finish() runs.
		_ = upWriter.Close()
		<-client.WaitClosed()

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("iter %d: post-WaitClosed Close panicked: %v", i, r)
				}
			}()
			_ = client.Close() // idempotent finish
		}()
	}

	time.Sleep(20 * time.Millisecond)
}
