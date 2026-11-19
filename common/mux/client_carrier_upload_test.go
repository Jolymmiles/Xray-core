package mux_test

import (
	"context"
	"errors"
	"io"
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

// An application that finishes its upload after the carrier failed still gets
// the reply the carrier had written. The end of an upload closes its session,
// and with it the application's side of the reply; once the carrier is gone
// the upload has nowhere to go, and taking it to its end must not cut off a
// reply the worker is still delivering. The application here reads nothing
// until its upload is done, and its pipe holds one frame, so the worker is
// held on the second.
func TestDialingWorkerKeepsQueuedReplyWhenUploadEndsAfterCarrierFails(t *testing.T) {
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
		<-worker.WaitClosed()
		synctest.Wait()

		block := buf.New()
		block.Extend(buf.Size)
		if err := uploadWriter.WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
			t.Fatal(err)
		}
		if err := uploadWriter.Close(); err != nil {
			t.Fatal(err)
		}
		// The upload has been taken as far as it goes.
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

// A session whose application went away is closed at once, also on a worker
// whose carrier has failed and whose reader is held by another session: that
// application reads slowly and may hold the reader for long, and nobody is
// left to read the abandoned session's reply.
func TestDialingWorkerEndsAnAbandonedSessionWhileItsReaderIsHeld(t *testing.T) {
	quietLogs(t)
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
		<-slowSink.accepted
		upload, _, reply, sink := newSession()
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
			t.Fatal("the worker refused the second session")
		}
		synctest.Wait()

		// The carrier writes the rest of the slow session's reply and fails;
		// the worker's reader is held on that frame.
		close(carrierMayEnd)
		<-worker.WaitClosed()
		synctest.Wait()
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
