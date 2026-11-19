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

	"github.com/xtls/xray-core/common"
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

// An application whose upload the failed carrier's uplink refused still gets
// the reply the carrier had written. The end of an upload ends its session,
// and with it the application's side of the reply; a refusal is not the
// application's doing, and the upload it cut short must not end the session
// under a reply the worker is still delivering. The application here sends
// four more buffers and ends its upload before it reads anything, and its
// reply pipe holds one frame, so the worker is held on the second. What it
// sends is taken from it: its upload pipe holds one write, and left unread
// would hold the application before it gets to read the reply.
func TestDialingWorkerKeepsQueuedReplyWhenUploadIsRefusedAfterCarrierFails(t *testing.T) {
	quietLogs(t)
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
// refused what it sent; or it ends its upload, which is also what closing a
// connection looks like to the session that reads it, and which ends a
// Mux.Cool session with a live carrier too.
func TestDialingWorkerEndsAnAbandonedSessionWhileItsReaderIsHeld(t *testing.T) {
	quietLogs(t)
	for name, uploads := range map[string]int{"before its first frame": 0, "in mid-upload": 1, "after a refused upload": 2} {
		t.Run(name, func(t *testing.T) { endsAbandonedSession(t, uploads, false) })
	}
	for name, uploads := range map[string]int{"ending an upload it never began": 0, "ending its upload": 1} {
		t.Run(name, func(t *testing.T) { endsAbandonedSession(t, uploads, true) })
	}
}

// endsAbandonedSession has the application send uploads blocks, the first
// while the carrier lives and the second after it failed, and leave: by an
// interrupt of its input, or by ending its upload.
func endsAbandonedSession(t *testing.T, uploads int, endsUpload bool) {
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

		if endsUpload {
			if err := send.Close(); err != nil {
				t.Fatal(err)
			}
		} else {
			upload.Interrupt()
		}
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

// The factory has closed the downlink's end, the worker and the uplink before
// it reports the carrier's error, so that the sessions get their replies and
// their end while a log handler takes its time; reported earlier, the error
// would keep them silent for as long. The session here is in the middle of an
// upload larger than the uplink holds, and its reply has no end of its own.
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
			withoutEnd: true,
		}
		worker, err := (&mux.DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		sendBlocks := func(count int) error {
			var blocks buf.MultiBuffer
			for range count {
				block := buf.New()
				block.Extend(buf.Size)
				blocks = append(blocks, block)
			}
			return uploadWriter.WriteMultiBuffer(blocks)
		}
		if err := sendBlocks(32); err != nil {
			t.Fatal(err)
		}
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

		// The report is still held. The uplink is interrupted: the upload
		// it held is released, and what the application sends is taken.
		sent := make(chan error, 1)
		go func() {
			for range 2 {
				if err := sendBlocks(1); err != nil {
					sent <- err
					return
				}
			}
			sent <- nil
		}()
		synctest.Wait()
		select {
		case err := <-sent:
			if err != nil {
				t.Fatalf("the upload failed: %v", err)
			}
		default:
			t.Fatal("the carrier's error is being reported and the application is held on its upload")
		}

		// The downlink is closed: the session gets its reply and its end.
		var body string
		for {
			data, err := reply.ReadMultiBufferTimeout(time.Second)
			body += data.String()
			buf.ReleaseMulti(data)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("the carrier's error is being reported; the application read %q, then: %v", body, err)
			}
		}
		if body != "firstlast" {
			t.Fatalf("the application read %q and then the end, want the whole reply %q", body, "firstlast")
		}
	})
}

// onceFailingInput is a session's input that is not a pipe: it gives one
// batch, then fails one read and stays usable, as a connection does whose
// owner put a deadline on a single read. The failing read may bring a last
// batch with its error.
type onceFailingInput struct {
	first buf.MultiBuffer
	last  buf.MultiBuffer
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
		return r.last, errors.New("i/o timeout")
	default:
		<-r.idle
		return nil, io.EOF
	}
}

// A session whose input fails is closed at once on a closed worker too, and
// its Dispatch returns. Its input is not read again for more: a reader that
// is not a pipe can fail once and then wait, behind another session's slow
// reader, for as long as that one holds the worker's reader. That holds
// when the failing read brings a last batch, which the uplink refuses.
func TestDialingWorkerEndsASessionWhoseInputFailsOnce(t *testing.T) {
	quietLogs(t)
	for name, withLastBatch := range map[string]bool{"an empty read": false, "a read with a last batch": true} {
		t.Run(name, func(t *testing.T) { endsSessionOfFailedInput(t, withLastBatch) })
	}
}

func endsSessionOfFailedInput(t *testing.T, withLastBatch bool) {
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
		if withLastBatch {
			last := buf.New()
			last.Extend(buf.Size)
			input.last = buf.MultiBuffer{last}
		}
		defer close(input.idle)
		failInput := sync.OnceFunc(func() { close(input.fail) })
		defer failInput()
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

		failInput()
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

// Once its session is seen to have ended, no read of an input whose upload is
// being dropped is begun. A wrapped reader does not pass on the interrupt a
// session's end gives its input, so one read may be waiting at that moment
// and takes one batch; what its owner sends after that is the owner's:
// Dispatch has returned by then.
func TestDialingWorkerStopsReadingAnInputOnceItsSessionEnded(t *testing.T) {
	quietLogs(t)
	synctest.Test(t, func(t *testing.T) {
		stop := make(chan struct{})
		defer close(stop)
		carrierMayEnd := make(chan struct{})
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

		input, send := pipe.New(pipe.WithSizeLimit(0))
		defer input.Interrupt()
		defer send.Close()
		reply, output := pipe.New()
		defer reply.Interrupt()
		// More than the uplink holds: the upload is in progress when the
		// carrier fails, and is refused.
		var request buf.MultiBuffer
		for size := 0; size < 256*1024; size += buf.Size {
			block := buf.New()
			block.Extend(buf.Size)
			request = append(request, block)
		}
		if err := send.WriteMultiBuffer(request); err != nil {
			t.Fatal(err)
		}
		dispatched := make(chan bool, 1)
		go func() {
			dispatched <- worker.Dispatch(ctx, &transport.Link{Reader: &buf.TimeoutWrapperReader{Reader: input}, Writer: output})
		}()
		synctest.Wait()

		close(carrierMayEnd)
		await(t, worker.WaitClosed(), "the worker to close")
		// The reply is read, so the worker's reader reaches the end of
		// the downlink and ends the session.
		for {
			data, err := reply.ReadMultiBufferTimeout(time.Second)
			buf.ReleaseMulti(data)
			if err != nil {
				break
			}
		}
		if !await(t, dispatched, "Dispatch to return") {
			t.Fatal("the worker refused the session")
		}
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 0 {
			t.Fatalf("%d sessions after the worker finished, want none", active)
		}

		// One read may have been waiting when the session ended. No other
		// follows it: of three writes into a pipe that holds one, the
		// third is not taken.
		taken := make(chan int, 1)
		go func() {
			for count := range 3 {
				block := buf.New()
				block.Extend(buf.Size)
				if err := send.WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
					taken <- count
					return
				}
			}
			taken <- 3
		}()
		synctest.Wait()
		select {
		case count := <-taken:
			t.Fatalf("the ended session's input was still read: %d writes taken after Dispatch returned", count)
		default:
		}
	})
}

// uplinkCarrier hands out its end of the uplink before it carries on as the
// carrier it wraps.
type uplinkCarrier struct {
	*answeringCarrier
	uplink chan buf.Reader
}

func (c *uplinkCarrier) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	c.uplink <- link.Reader
	return c.answeringCarrier.Process(ctx, link, dialer)
}

// heldUploadReport is a log handler that holds the report of a failed upload.
type heldUploadReport struct {
	once    *sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (h heldUploadReport) Handle(message log.Message) {
	if strings.Contains(message.String(), "failed to fetch all input") {
		h.once.Do(func() { close(h.entered) })
		<-h.resume
	}
}

// An upload the uplink refused while the worker was open ends its session,
// also when the carrier returns before that refusal has been reported: what
// counts is the worker's state when the write failed. A carrier can
// interrupt its uplink before it returns, and a log handler takes its time.
func TestDialingWorkerEndsASessionRefusedWhileOpenThoughItsCarrierReturnsMeanwhile(t *testing.T) {
	quietLogs(t)
	synctest.Test(t, func(t *testing.T) {
		report := heldUploadReport{once: new(sync.Once), entered: make(chan struct{}), resume: make(chan struct{})}
		log.RegisterHandler(report)
		release := sync.OnceFunc(func() { close(report.resume) })
		defer release()
		defer log.RegisterHandler(discardLogs{})

		stop := make(chan struct{})
		defer close(stop)
		carrierMayEnd := make(chan struct{})
		carrier := &uplinkCarrier{
			answeringCarrier: &answeringCarrier{
				delivering: carrierMayEnd,
				stop:       stop,
				result:     errors.New("connection reset"),
				returned:   make(chan struct{}),
			},
			uplink: make(chan buf.Reader, 1),
		}
		worker, err := (&mux.DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		uplink := await(t, carrier.uplink, "the carrier to start")
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})

		// A slow session holds the worker's reader once the carrier is gone,
		// so that the other session is not ended by the worker's cleanup.
		slowUpload, slowSend := pipe.New()
		defer slowSend.Close()
		slowReply, slowOutput := pipe.New(pipe.WithSizeLimit(0))
		defer slowReply.Interrupt()
		slowSink := &acceptedWriter{Writer: slowOutput, accepted: make(chan struct{})}
		if !worker.Dispatch(ctx, &transport.Link{Reader: slowUpload, Writer: slowSink}) {
			t.Fatal("the worker refused the first session")
		}
		await(t, slowSink.accepted, "the first frame of the slow session's reply")

		upload, send := pipe.New()
		defer send.Close()
		reply, output := pipe.New()
		defer reply.Interrupt()
		sendBlock := func() {
			block := buf.New()
			block.Extend(buf.Size)
			if err := send.WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
				t.Fatal(err)
			}
		}
		sendBlock()
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: output}) {
			t.Fatal("the worker refused the second session")
		}
		synctest.Wait()

		// The carrier stops taking the upload and has not returned.
		common.Interrupt(uplink)
		sendBlock()
		await(t, report.entered, "the report of the refused upload")
		if worker.Closed() {
			t.Fatal("the worker closed before the upload was refused")
		}

		// The carrier returns while that report is held.
		close(carrierMayEnd)
		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()
		release()
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 1 {
			t.Fatalf("%d sessions after the refused upload was reported, want the slow one only", active)
		}
	})
}

// lastBatchInput is a session's input that is not a pipe and whose one batch
// comes with the result that ends it: the end of the input, or an error.
type lastBatchInput struct {
	ready  <-chan struct{}
	result error
	reads  int
}

func (r *lastBatchInput) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.reads++
	if r.reads > 1 {
		return nil, io.EOF
	}
	if r.ready != nil {
		<-r.ready
	}
	block := buf.New()
	if _, err := block.WriteString("tail"); err != nil {
		block.Release()
		return nil, err
	}
	return buf.MultiBuffer{block}, r.result
}

// A batch the uplink refuses may be the upload's last, its read bringing the
// end of the input with it. That upload ran to its end: the session is kept
// for its reply and the input is not read again.
func TestDialingWorkerKeepsQueuedReplyWhenTheRefusedBatchIsTheLast(t *testing.T) {
	quietLogs(t)
	synctest.Test(t, func(t *testing.T) {
		reply, output := pipe.New(pipe.WithSizeLimit(0))
		defer reply.Interrupt()
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
		carrierGone := make(chan struct{})
		release := sync.OnceFunc(func() { close(carrierGone) })
		defer release()
		input := &lastBatchInput{ready: carrierGone, result: io.EOF}
		dispatched := make(chan bool, 1)
		go func() { dispatched <- worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: sink}) }()

		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()
		release()
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
		if body != "firstlast" || input.reads != 1 {
			t.Fatalf("the application read %q after %d reads of its input, want the whole reply %q after one", body, input.reads, "firstlast")
		}
		if !await(t, dispatched, "Dispatch to return") {
			t.Fatal("the worker refused the session")
		}
	})
}

// The last batch of an upload reaches the peer when its read also brings the
// result that ends the upload, and the END that follows says whether the
// upload ended or failed.
func TestClientWorkerSendsTheLastBatchAndMarksAFailedUpload(t *testing.T) {
	quietLogs(t)
	for name, result := range map[string]error{"the input ends": io.EOF, "the input fails": errors.New("read deadline")} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				uplink, uplinkWriter := pipe.New()
				defer uplink.Interrupt()
				downlink, downlinkWriter := pipe.New()
				defer downlinkWriter.Close()
				worker, err := mux.NewClientWorker(transport.Link{Reader: downlink, Writer: uplinkWriter}, mux.ClientStrategy{})
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close()
				reply, output := pipe.New()
				defer reply.Interrupt()
				input := &lastBatchInput{result: result}
				ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
					Target: net.TCPDestination(net.LocalHostIP, 80),
				}})
				if !worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: output}) {
					t.Fatal("the worker refused the session")
				}
				synctest.Wait()

				frames := &buf.BufferedReader{Reader: uplink}
				defer func() { buf.ReleaseMulti(frames.Buffer) }()
				var frame mux.FrameMetadata
				if err := frame.Unmarshal(frames, false); err != nil {
					t.Fatal(err)
				}
				if frame.SessionStatus != mux.SessionStatusNew {
					t.Fatalf("the first frame is %+v, want a NEW", frame)
				}
				if err := frame.Unmarshal(frames, false); err != nil {
					t.Fatal(err)
				}
				if frame.SessionStatus != mux.SessionStatusKeep || !frame.Option.Has(mux.OptionData) {
					t.Fatalf("the frame after NEW is %+v, want the last batch", frame)
				}
				data, err := mux.NewStreamReader(frames).ReadMultiBuffer()
				defer buf.ReleaseMulti(data)
				if (err != nil && !errors.Is(err, io.EOF)) || data.String() != "tail" {
					t.Fatalf("the last batch is %q (%v), want %q", data.String(), err, "tail")
				}
				if err := frame.Unmarshal(frames, false); err != nil {
					t.Fatal(err)
				}
				failed := !errors.Is(result, io.EOF)
				if frame.SessionStatus != mux.SessionStatusEnd || frame.Option.Has(mux.OptionError) != failed {
					t.Fatalf("the last frame is %+v, want an END marked as failed: %v", frame, failed)
				}
				if input.reads != 1 {
					t.Fatalf("the input was read %d times, want once", input.reads)
				}
			})
		})
	}
}
