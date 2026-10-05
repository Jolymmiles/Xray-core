package hysteria

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// retainedWriterDispatcher keeps link.Writer after DispatchLink returns, as
// mux.ServerWorker does for its per-session handle goroutines, which write the
// session End frame after the carrier dispatch has already completed.
type retainedWriterDispatcher struct {
	routing.Dispatcher
	writer buf.Writer
}

func (d *retainedWriterDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	d.writer = link.Writer
	return nil
}

func TestServerTCPWriterSurvivesProcessReturn(t *testing.T) {
	address := "v1.mux.cool:0"
	wire := append([]byte{byte(len(address))}, address...)
	wire = append(wire, 0)
	var output bytes.Buffer
	conn := cnc.NewConnection(cnc.ConnectionOutput(bytes.NewReader(wire)), cnc.ConnectionInput(&output))
	defer conn.Close()
	dispatcher := new(retainedWriterDispatcher)
	ctx := session.ContextWithInbound(context.Background(), new(session.Inbound))
	if err := new(Server).Process(ctx, net.Network_TCP, requestConnection{conn}, dispatcher); err != nil {
		t.Fatal(err)
	}
	responseLength := output.Len()

	// A later carrier on the same server must not be able to take over the
	// retained writer.
	nextConn := cnc.NewConnection(cnc.ConnectionOutput(bytes.NewReader(wire)), cnc.ConnectionInput(io.Discard))
	defer nextConn.Close()
	if err := new(Server).Process(ctx, net.Network_TCP, requestConnection{nextConn}, new(retainedWriterDispatcher)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("late mux end frame")
	if err := dispatcher.writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
		t.Fatalf("late write through retained writer: %v", err)
	}
	if got := output.Bytes()[responseLength:]; !bytes.Equal(got, payload) {
		t.Fatalf("late write reached carrier as %q, want %q", got, payload)
	}
}

// overlapDetectingConn fails a write that starts while another write through
// the same carrier is still in progress.
type overlapDetectingConn struct {
	inFlight atomic.Int32
	overlaps atomic.Int32
}

func (c *overlapDetectingConn) Write(p []byte) (int, error) {
	if c.inFlight.Add(1) != 1 {
		c.overlaps.Add(1)
	}
	runtime.Gosched()
	c.inFlight.Add(-1)
	return len(p), nil
}

// Mux.Cool session handlers write frames through the carrier writer from
// separate goroutines. Each frame is one MultiBuffer (header, payload); the
// carrier writer must serialize whole MultiBuffers so frames of concurrent
// sessions never interleave on the stream.
func TestServerTCPWriterSerializesConcurrentMultiBuffers(t *testing.T) {
	address := "v1.mux.cool:0"
	wire := append([]byte{byte(len(address))}, address...)
	wire = append(wire, 0)
	carrier := new(overlapDetectingConn)
	conn := cnc.NewConnection(cnc.ConnectionOutput(bytes.NewReader(wire)), cnc.ConnectionInput(carrier))
	defer conn.Close()
	dispatcher := new(retainedWriterDispatcher)
	ctx := session.ContextWithInbound(context.Background(), new(session.Inbound))
	if err := new(Server).Process(ctx, net.Network_TCP, requestConnection{conn}, dispatcher); err != nil {
		t.Fatal(err)
	}

	const (
		sessions = 16
		frames   = 200
	)
	var wg sync.WaitGroup
	for range sessions {
		wg.Go(func() {
			for range frames {
				frame := buf.MultiBuffer{buf.FromBytes([]byte("header")), buf.FromBytes([]byte("payload"))}
				if err := dispatcher.writer.WriteMultiBuffer(frame); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	if overlaps := carrier.overlaps.Load(); overlaps != 0 {
		t.Fatalf("carrier saw %d overlapping writes from concurrent MultiBuffers", overlaps)
	}
}
