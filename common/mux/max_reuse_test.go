package mux_test

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// echoCarrierFactory connects every new client carrier to its own server
// worker, whose dispatcher echoes each session back to the client.
type echoCarrierFactory struct {
	strategy mux.ClientStrategy

	mu      sync.Mutex
	workers []*mux.ClientWorker
}

func (f *echoCarrierFactory) Create() (*mux.ClientWorker, error) {
	serverLink, clientLink := newLinkPair()
	serverCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	echo := &TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		reader, writer := pipe.New(pipe.WithoutSizeLimit())
		return &transport.Link{Reader: reader, Writer: writer}, nil
	}}
	if _, err := mux.NewServerWorker(serverCtx, echo, serverLink); err != nil {
		return nil, err
	}
	worker, err := mux.NewClientWorker(*clientLink, f.strategy)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.workers = append(f.workers, worker)
	f.mu.Unlock()
	return worker, nil
}

func (f *echoCarrierFactory) carriers() []*mux.ClientWorker {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*mux.ClientWorker(nil), f.workers...)
}

type echoSession struct {
	upload   *pipe.Writer
	download *pipe.Reader
}

func openEchoSession(t *testing.T, manager *mux.ClientManager) *echoSession {
	t.Helper()
	uploadReader, uploadWriter := pipe.New(pipe.WithoutSizeLimit())
	downloadReader, downloadWriter := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	if err := manager.Dispatch(ctx, &transport.Link{Reader: uploadReader, Writer: downloadWriter}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return &echoSession{upload: uploadWriter, download: downloadReader}
}

func (s *echoSession) echo(t *testing.T, payload string) {
	t.Helper()
	if err := s.upload.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte(payload))}); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	var got []byte
	for len(got) < len(payload) {
		mb, err := s.download.ReadMultiBufferTimeout(5 * time.Second)
		if err != nil {
			t.Fatalf("read echo of %q after %q: %v", payload, got, err)
		}
		for _, b := range mb {
			got = append(got, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
	}
	if string(got) != payload {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func (s *echoSession) close() {
	_ = s.upload.Close()
}

// Once a carrier has admitted its lifetime budget of sessions
// (ClientStrategy.MaxConnection, an outbound's mux.maxReuseTimes), the next
// session opens a new carrier. The sessions already on the exhausted carrier
// keep flowing both ways, and the exhausted carrier retires only after its
// last session ends.
func TestClientManagerReplacesExhaustedCarrier(t *testing.T) {
	quietLogs(t)
	synctest.Test(t, func(t *testing.T) {
		// Concurrency above the budget, so the budget alone decides.
		factory := &echoCarrierFactory{strategy: mux.ClientStrategy{MaxConcurrency: 8, MaxConnection: 2}}
		manager := &mux.ClientManager{Enabled: true, Picker: &mux.IncrementalWorkerPicker{Factory: factory}}
		// Closing a client carrier ends its sessions and its server worker.
		t.Cleanup(func() {
			for _, carrier := range factory.carriers() {
				_ = carrier.Close()
			}
		})

		first := openEchoSession(t, manager)
		second := openEchoSession(t, manager)
		first.echo(t, "first, before the new carrier")
		second.echo(t, "second, before the new carrier")
		if n := len(factory.carriers()); n != 1 {
			t.Fatalf("%d carriers within the budget, want 1", n)
		}

		third := openEchoSession(t, manager)
		third.echo(t, "third, on the new carrier")
		carriers := factory.carriers()
		if len(carriers) != 2 {
			t.Fatalf("%d carriers after the budget ran out, want 2", len(carriers))
		}
		exhausted, replacement := carriers[0], carriers[1]
		if !exhausted.IsFull() || exhausted.Closed() {
			t.Fatalf("exhausted carrier: full %t, closed %t; want full and still open", exhausted.IsFull(), exhausted.Closed())
		}
		first.echo(t, "first, after the new carrier")
		second.echo(t, "second, after the new carrier")

		first.close()
		second.close()
		// The idle check retires a carrier on the second 16-second tick
		// that finds it empty.
		time.Sleep(40 * time.Second)
		synctest.Wait()
		if !exhausted.Closed() {
			t.Fatal("exhausted carrier still open after its last session ended")
		}
		if replacement.Closed() {
			t.Fatal("replacement carrier closed while it carried a session")
		}
		third.echo(t, "third, after the old carrier retired")
	})
}
