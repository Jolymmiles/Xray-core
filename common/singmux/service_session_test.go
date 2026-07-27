package singmux

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/transport"
)

// sessionStateDispatcher performs the writes and reads the real dispatcher does
// on the per-connection Outbound: DispatchLink sets ob.Target, then the router
// matchers and the dialer read it back while other streams are dispatching.
type sessionStateDispatcher struct {
	*echoDispatcher
	dispatched sync.WaitGroup
	mismatches atomic.Int32
	shared     atomic.Int32
	seen       sync.Map
}

func (d *sessionStateDispatcher) DispatchLink(ctx context.Context, destination X.Destination, _ *transport.Link) error {
	defer d.dispatched.Done()
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		d.mismatches.Add(1)
		return nil
	}
	ob := outbounds[len(outbounds)-1]
	if _, loaded := d.seen.LoadOrStore(ob, destination); loaded {
		d.shared.Add(1)
	}

	// app/dispatcher.DispatchLink
	ob.OriginalTarget = destination
	ob.Target = destination
	// proxy/freedom.Process
	ob.Name = "freedom"
	content := session.ContentFromContext(ctx)
	if content != nil {
		content.SkipSniffingAttributes = true
	}

	// Widen the window between the dispatcher's write and the reads that
	// app/router and transport/internet.DialSystem perform on the same fields.
	time.Sleep(2 * time.Millisecond)

	if ob.Target != destination || ob.OriginalTarget != destination {
		d.mismatches.Add(1)
	}
	return nil
}

// TestServiceIsolatesSessionStatePerStream fails under -race before the
// per-stream context fix: every stream of one carrier shared the carrier's
// Outbound and Content.
func TestServiceIsolatesSessionStatePerStream(t *testing.T) {
	const streams = 16

	dispatcher := &sessionStateDispatcher{echoDispatcher: &echoDispatcher{target: make(chan X.Destination, streams)}}
	dispatcher.dispatched.Add(streams)
	service := NewService(dispatcher)

	clientConnection, serverConnection := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// A carrier context shaped like the one an inbound worker installs: a single
	// Outbound and Content shared by everything dispatched on it.
	carrierCtx := session.ContextWithConnection(ctx, 1,
		session.Inbound{Tag: "in"},
		session.Outbound{},
		session.Content{},
	)
	go func() { _ = service.NewConnection(carrierCtx, serverConnection) }()

	if err := writeCarrierRequest(clientConnection, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	carrier, err := localsmux.Client(clientConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = carrier.Close() })

	var opened sync.WaitGroup
	for i := range streams {
		opened.Add(1)
		go func() {
			defer opened.Done()
			stream, err := carrier.OpenStream()
			if err != nil {
				t.Error(err)
				dispatcher.dispatched.Done()
				return
			}
			defer stream.Close()
			// Alternate domain and IP targets: the production panic needs a
			// matcher to read an IP target that a neighbour replaced with a domain.
			destination := X.TCPDestination(X.DomainAddress("example.org"), 443)
			if i%2 == 0 {
				destination = X.TCPDestination(X.IPAddress([]byte{1, 1, 1, byte(i)}), 443)
			}
			if err := writeStreamRequest(stream, 0, destination); err != nil {
				t.Error(err)
				dispatcher.dispatched.Done()
				return
			}
			if err := readStreamResponse(stream); err != nil {
				t.Error(err)
				dispatcher.dispatched.Done()
				return
			}
		}()
	}
	opened.Wait()

	done := make(chan struct{})
	go func() {
		dispatcher.dispatched.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for streams to dispatch")
	}

	if shared := dispatcher.shared.Load(); shared != 0 {
		t.Errorf("%d streams reused another stream's session.Outbound, want each stream its own", shared)
	}
	if mismatches := dispatcher.mismatches.Load(); mismatches != 0 {
		t.Errorf("%d streams observed a target overwritten by a concurrent stream", mismatches)
	}
}
