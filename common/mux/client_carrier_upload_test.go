package mux_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

// acceptedWriter reports its first write that the pipe took.
type acceptedWriter struct {
	*pipe.Writer
	once     sync.Once
	accepted chan struct{}
}

func (w *acceptedWriter) WriteMultiBuffer(data buf.MultiBuffer) error {
	err := w.Writer.WriteMultiBuffer(data)
	if err == nil {
		w.once.Do(func() { close(w.accepted) })
	}
	return err
}

// await waits for a signal, for no longer than a test's clock allows: a
// worker keeps a ticker, so a signal that never comes would not end a
// synctest bubble.
func await[T any](t *testing.T, signal <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-signal:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("waited 5s for %s", what)
		panic("unreachable")
	}
}

// An application that finishes its upload after the carrier failed still gets
// the reply the carrier had written. The end of an upload closes its session,
// and with it the application's side of the reply; once the carrier is gone
// the upload has nowhere to go, and taking it to its end must not cut off a
// reply the worker is still delivering. The application here reads nothing
// until its upload is done, and its pipe holds one frame, so the worker is
// held on the second. Its upload ends with more to send, which the uplink
// refuses, or with nothing left. What it still sends is taken from it: its
// pipe holds one write, and left unread would hold the application before it
// gets to read the reply.
func TestDialingWorkerKeepsQueuedReplyWhenUploadEndsAfterCarrierFails(t *testing.T) {
	quietLogs(t)
	for name, sendsMore := range map[string]bool{"refused": true, "ended": false} {
		t.Run(name, func(t *testing.T) { keepsQueuedReply(t, sendsMore) })
	}
}

func keepsQueuedReply(t *testing.T, sendsMore bool) {
	synctest.Test(t, func(t *testing.T) {
		upload, uploadWriter := pipe.New(pipe.WithSizeLimit(0))
		reply, output := pipe.New(pipe.WithSizeLimit(0))
		defer reply.Interrupt()
		defer uploadWriter.Close()
		sink := &acceptedWriter{Writer: output, accepted: make(chan struct{})}
		stop := make(chan struct{})
		defer close(stop)

		carrier := &answeringCarrier{
			delivering: sink.accepted,
			stop:       stop,
			result:     errors.New("connection reset"),
			returned:   make(chan struct{}),
		}
		worker, err := (&mux.DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()

		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
			t.Fatal("the worker refused the session")
		}
		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()

		sent := make(chan error, 1)
		go func() {
			for range 4 {
				if !sendsMore {
					break
				}
				block := buf.New()
				block.Extend(buf.Size)
				if err := uploadWriter.WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
					sent <- err
					return
				}
			}
			sent <- uploadWriter.Close()
		}()
		// The upload has been taken as far as it goes.
		synctest.Wait()
		select {
		case err := <-sent:
			if err != nil {
				t.Fatalf("the upload failed: %v", err)
			}
		default:
			t.Fatal("the application is held on its upload, with its reply unread")
		}

		var body string
		for {
			data, err := reply.ReadMultiBufferTimeout(time.Second)
			body += data.String()
			buf.ReleaseMulti(data)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("read %q, then: %v", body, err)
			}
		}
		if body != "firstlast" {
			t.Fatalf("the application read %q and then the end, want the whole reply %q", body, "firstlast")
		}
	})
}

// A session whose application went away is closed at once, also on a worker
// whose carrier has failed and whose reader is held by another session: that
// application reads slowly and may hold the reader for long, and nobody is
// left to read the abandoned session's reply. The application leaves before
// it has sent anything, in the middle of its upload, or after the uplink has
// refused what it sent.
func TestDialingWorkerEndsAnAbandonedSessionWhileItsReaderIsHeld(t *testing.T) {
	quietLogs(t)
	for name, uploads := range map[string]int{"before its first frame": 0, "in mid-upload": 1, "after a refused upload": 2} {
		t.Run(name, func(t *testing.T) { endsAbandonedSession(t, uploads) })
	}
}

// endsAbandonedSession has the application send uploads blocks, the first
// while the carrier lives and the second after it failed, and leave.
func endsAbandonedSession(t *testing.T, uploads int) {
	synctest.Test(t, func(t *testing.T) {
		newSession := func() (upload *pipe.Reader, send *pipe.Writer, reply *pipe.Reader, sink *acceptedWriter) {
			upload, send = pipe.New(pipe.WithSizeLimit(0))
			reply, output := pipe.New(pipe.WithSizeLimit(0))
			t.Cleanup(func() { _ = send.Close(); reply.Interrupt() })
			return upload, send, reply, &acceptedWriter{Writer: output, accepted: make(chan struct{})}
		}
		slowUpload, _, _, slowSink := newSession()
		carrierMayEnd := make(chan struct{})
		stop := make(chan struct{})
		defer close(stop)
		carrier := &answeringCarrier{
			delivering: carrierMayEnd,
			stop:       stop,
			result:     errors.New("connection reset"),
			returned:   make(chan struct{}),
		}
		worker, err := (&mux.DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()

		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: slowUpload, Writer: slowSink}) {
			t.Fatal("the worker refused the first session")
		}
		// The slow application's pipe holds the first frame of its reply.
		await(t, slowSink.accepted, "the first frame of the slow session's reply")
		upload, send, reply, sink := newSession()
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
			t.Fatal("the worker refused the second session")
		}
		sendBlock := func() {
			block := buf.New()
			block.Extend(buf.Size)
			if err := send.WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
				t.Fatal(err)
			}
		}
		if uploads >= 1 {
			sendBlock()
		}
		synctest.Wait()

		// The carrier writes the rest of the slow session's reply and fails;
		// the worker's reader is held on that frame.
		close(carrierMayEnd)
		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()
		if uploads >= 2 {
			sendBlock()
			synctest.Wait()
		}
		if active := worker.ActiveConnections(); active != 2 {
			t.Fatalf("%d sessions before the application left, want 2", active)
		}

		upload.Interrupt()
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 1 {
			t.Fatalf("%d sessions after one application left, want the slow one only", active)
		}
		data, err := reply.ReadMultiBufferTimeout(time.Second)
		buf.ReleaseMulti(data)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("the abandoned session's reply did not end: %v", err)
		}
	})
}

// idleCarrier is an outbound whose carrier stays up until released and
// carries nothing.
type idleCarrier struct{ release chan struct{} }

func (c idleCarrier) Process(context.Context, *transport.Link, internet.Dialer) error {
	<-c.release
	return nil
}

// While the carrier lives, the end of an upload still ends its session: the
// exception above is for a closed worker only.
func TestDialingWorkerEndsASessionWithItsUploadWhileCarrierLives(t *testing.T) {
	quietLogs(t)
	synctest.Test(t, func(t *testing.T) {
		carrier := idleCarrier{release: make(chan struct{})}
		defer close(carrier.release)
		worker, err := (&mux.DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()

		upload, uploadWriter := pipe.New(pipe.WithSizeLimit(0))
		reply, output := pipe.New(pipe.WithSizeLimit(0))
		defer reply.Interrupt()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: output}) {
			t.Fatal("the worker refused the session")
		}
		request := buf.New()
		request.Extend(buf.Size)
		if err := uploadWriter.WriteMultiBuffer(buf.MultiBuffer{request}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 1 {
			t.Fatalf("%d sessions in mid-upload, want 1", active)
		}
		if err := uploadWriter.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()

		if worker.Closed() {
			t.Fatal("the worker closed under a live carrier")
		}
		if active := worker.ActiveConnections(); active != 0 {
			t.Fatalf("%d sessions after the upload ended, want none", active)
		}
		data, err := reply.ReadMultiBufferTimeout(time.Second)
		buf.ReleaseMulti(data)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("the session's reply did not end with its upload: %v", err)
		}
	})
}

// heldReport is a log handler that holds the report of a failed carrier.
type heldReport struct {
	once    *sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (h heldReport) Handle(message log.Message) {
	if strings.Contains(message.String(), "failed to handler mux client connection") {
		h.once.Do(func() { close(h.entered) })
		<-h.resume
	}
}

// The worker is closed before the carrier's error is reported. A log handler
// takes its time, and an upload that ended meanwhile, on a worker still open,
// would close its session under the reply the carrier had written.
func TestDialingWorkerClosesBeforeItReportsItsCarrier(t *testing.T) {
	quietLogs(t)
	synctest.Test(t, func(t *testing.T) {
		// The handler's channels belong to the bubble, so the handler is
		// set here and taken away again before the bubble ends.
		report := heldReport{once: new(sync.Once), entered: make(chan struct{}), resume: make(chan struct{})}
		log.RegisterHandler(report)
		defer close(report.resume)
		defer log.RegisterHandler(discardLogs{})

		upload, uploadWriter := pipe.New(pipe.WithSizeLimit(0))
		reply, output := pipe.New(pipe.WithSizeLimit(0))
		defer reply.Interrupt()
		defer uploadWriter.Close()
		sink := &acceptedWriter{Writer: output, accepted: make(chan struct{})}
		stop := make(chan struct{})
		defer close(stop)
		carrier := &answeringCarrier{
			delivering: sink.accepted,
			stop:       stop,
			result:     errors.New("connection reset"),
			returned:   make(chan struct{}),
		}
		worker, err := (&mux.DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
			t.Fatal("the worker refused the session")
		}
		await(t, report.entered, "the report of the carrier's error")
		if !worker.Closed() {
			t.Fatal("the carrier's error is being reported and the worker is still open")
		}
		if err := uploadWriter.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()

		var body string
		for {
			data, err := reply.ReadMultiBufferTimeout(time.Second)
			body += data.String()
			buf.ReleaseMulti(data)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("read %q, then: %v", body, err)
			}
		}
		if body != "firstlast" {
			t.Fatalf("the application read %q and then the end, want the whole reply %q", body, "firstlast")
		}
	})
}

// onceFailingInput is a session's input that is not a pipe: it gives one
// batch, then fails one read and stays usable, as a connection does whose
// owner put a deadline on a single read.
type onceFailingInput struct {
	first buf.MultiBuffer
	fail  chan struct{}
	idle  chan struct{}
	state int
}

func (r *onceFailingInput) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.state++
	switch r.state {
	case 1:
		return r.first, nil
	case 2:
		<-r.fail
		return nil, errors.New("i/o timeout")
	default:
		<-r.idle
		return nil, io.EOF
	}
}

// A session whose input fails is closed at once on a closed worker too, and
// its Dispatch returns. Its input is not read again for more: a reader that
// is not a pipe can fail once and then wait, behind another session's slow
// reader, for as long as that one holds the worker's reader.
func TestDialingWorkerEndsASessionWhoseInputFailsOnce(t *testing.T) {
	quietLogs(t)
	synctest.Test(t, func(t *testing.T) {
		slowUpload, slowSend := pipe.New(pipe.WithSizeLimit(0))
		defer slowSend.Close()
		slowReply, slowOutput := pipe.New(pipe.WithSizeLimit(0))
		defer slowReply.Interrupt()
		slowSink := &acceptedWriter{Writer: slowOutput, accepted: make(chan struct{})}
		carrierMayEnd := make(chan struct{})
		stop := make(chan struct{})
		defer close(stop)
		carrier := &answeringCarrier{
			delivering: carrierMayEnd,
			stop:       stop,
			result:     errors.New("connection reset"),
			returned:   make(chan struct{}),
		}
		worker, err := (&mux.DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: slowUpload, Writer: slowSink}) {
			t.Fatal("the worker refused the first session")
		}
		await(t, slowSink.accepted, "the first frame of the slow session's reply")

		block := buf.New()
		block.Extend(buf.Size)
		input := &onceFailingInput{first: buf.MultiBuffer{block}, fail: make(chan struct{}), idle: make(chan struct{})}
		defer close(input.idle)
		reply, output := pipe.New(pipe.WithSizeLimit(0))
		defer reply.Interrupt()
		// Dispatch waits for the session when its input is not a pipe.
		dispatched := make(chan bool, 1)
		go func() { dispatched <- worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: output}) }()
		synctest.Wait()

		close(carrierMayEnd)
		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 2 {
			t.Fatalf("%d sessions before the input failed, want 2", active)
		}

		close(input.fail)
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 1 {
			t.Fatalf("%d sessions after one input failed, want the slow one only", active)
		}
		select {
		case accepted := <-dispatched:
			if !accepted {
				t.Fatal("the worker refused the second session")
			}
		default:
			t.Fatal("Dispatch still waits for a session whose input failed")
		}
	})
}
