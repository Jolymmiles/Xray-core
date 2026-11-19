package mux_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
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
	release := sync.OnceFunc(func() { close(carrier.release) })
	factory := &mux.DialingWorkerFactory{Proxy: carrier, Strategy: mux.ClientStrategy{MaxConcurrency: 8}}
	worker, err := factory.Create()
	if err != nil {
		t.Fatal(err)
	}
	// Also on a failure below: the carrier and the worker's readers end.
	defer worker.Close()
	defer release()
	input, inputWriter := pipe.New(pipe.WithoutSizeLimit())
	defer inputWriter.Close()
	outputReader, output := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.LocalHostIP, 80),
	}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: output}) {
		t.Fatal("worker refused the session")
	}
	release()

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

// heldWriter holds its first write until resumed: a session's application
// that reads slowly, so that the worker is still delivering one frame while
// the carrier writes the rest and ends.
type heldWriter struct {
	*pipe.Writer
	first   sync.Once
	writing chan struct{}
	resume  chan struct{}
}

func (w *heldWriter) WriteMultiBuffer(data buf.MultiBuffer) error {
	w.first.Do(func() { close(w.writing); <-w.resume })
	return w.Writer.WriteMultiBuffer(data)
}

// answeringCarrier answers the worker's first session with two frames and an
// end, waiting between the frames until the first is being delivered, then
// returns result. With a nil result it has closed the downlink as VLESS does;
// with an error it leaves it open. With withoutEnd it does not send the end,
// as a carrier that fails in the middle of a reply.
type answeringCarrier struct {
	delivering <-chan struct{}
	stop       <-chan struct{} // closed when the test ends, whatever it saw
	result     error
	returned   chan struct{}
	withoutEnd bool
}

func (c *answeringCarrier) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	defer close(c.returned)
	var request mux.FrameMetadata
	if err := request.Unmarshal(&buf.BufferedReader{Reader: link.Reader}, false); err != nil {
		return err
	}
	response := mux.NewResponseWriter(request.SessionID, link.Writer, protocol.TransferTypeStream)
	send := func(text string) error {
		b := buf.New()
		if _, err := b.WriteString(text); err != nil {
			b.Release()
			return err
		}
		return response.WriteMultiBuffer(buf.MultiBuffer{b})
	}
	if err := send("first"); err != nil {
		return err
	}
	select {
	case <-c.delivering:
	case <-c.stop:
		return errors.New("the test ended before the first frame was delivered")
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := send("last"); err != nil {
		return err
	}
	if !c.withoutEnd {
		if err := response.Close(); err != nil {
			return err
		}
	}
	if c.result != nil {
		return c.result
	}
	return common.Close(link.Writer)
}

// A response the carrier had written reaches its session when the carrier
// then ends, cleanly or with an error such as another session's failed
// write. Tearing the worker down at once would hand the application an end
// of stream in place of a response the server did send.
func TestDialingWorkerDeliversWhatItsCarrierWroteBeforeEnding(t *testing.T) {
	for name, result := range map[string]error{
		"clean end": nil,
		"failure":   errors.New("write on a closed tunnel"),
	} {
		t.Run(name, func(t *testing.T) {
			input, inputWriter := pipe.New()
			defer inputWriter.Close()
			reader, output := pipe.New()
			sink := &heldWriter{Writer: output, writing: make(chan struct{}), resume: make(chan struct{})}
			resume := sync.OnceFunc(func() { close(sink.resume) })
			defer resume()
			stop := make(chan struct{})
			defer close(stop)
			carrier := &answeringCarrier{delivering: sink.writing, stop: stop, result: result, returned: make(chan struct{})}
			factory := mux.DialingWorkerFactory{Proxy: carrier}
			worker, err := factory.Create()
			if err != nil {
				t.Fatal(err)
			}
			defer worker.Close()
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
				Target: net.TCPDestination(net.LocalHostIP, 80),
			}})
			if !worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: sink}) {
				t.Fatal("worker refused the session")
			}
			select {
			case <-carrier.returned:
			case <-time.After(5 * time.Second):
				t.Fatal("the carrier did not end")
			}
			// The factory marks the worker closed once it has dealt with
			// the carrier's end; only then does the application read on.
			select {
			case <-worker.WaitClosed():
			case <-time.After(5 * time.Second):
				t.Fatal("the worker was not closed after its carrier ended")
			}
			resume()

			type read struct {
				data []byte
				err  error
			}
			done := make(chan read, 1)
			go func() {
				data, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
				done <- read{data, err}
			}()
			select {
			case got := <-done:
				if got.err != nil || string(got.data) != "firstlast" {
					t.Fatalf("the application read %q (%v), want %q", got.data, got.err, "firstlast")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the session did not end after its carrier did")
			}
		})
	}
}
