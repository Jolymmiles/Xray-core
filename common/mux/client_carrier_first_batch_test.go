package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// takenWriter reports its first write that the pipe took.
type takenWriter struct {
	*pipe.Writer
	once  sync.Once
	taken chan struct{}
}

func (w *takenWriter) WriteMultiBuffer(data buf.MultiBuffer) error {
	err := w.Writer.WriteMultiBuffer(data)
	if err == nil {
		w.once.Do(func() { close(w.taken) })
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

// openingOnly lets one write through to the uplink and holds the next until
// released: the frame that opens a session reaches the carrier and nothing
// after it does.
type openingOnly struct {
	*MutexWriter
	opened  bool
	release <-chan struct{}
}

func (w *openingOnly) WriteMultiBuffer(data buf.MultiBuffer) error {
	if w.opened {
		<-w.release
	}
	w.opened = true
	return w.MutexWriter.WriteMultiBuffer(data)
}

// The first thing a session uploads goes out as one frame that opens the
// session and as many more as its size needs. A carrier that took the
// opening frame, answered in full and then failed leaves the rest of that
// upload refused; the application still gets the reply. Stream and packet
// sessions split their upload differently and both do. The uplink takes the
// frames it has room for, or the opening frame alone.
func TestDialingWorkerKeepsQueuedReplyWhenFirstUploadIsCutShort(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	for _, target := range []net.Destination{
		net.TCPDestination(net.LocalHostIP, 80),
		net.UDPDestination(net.LocalHostIP, 53),
	} {
		for name, openingAlone := range map[string]bool{"/several frames": false, "/opening frame alone": true} {
			t.Run(target.Network.String()+name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) { keepsReplyOfCutFirstUpload(t, target, openingAlone) })
			})
		}
	}
}

func keepsReplyOfCutFirstUpload(t *testing.T, target net.Destination, openingAlone bool) {
	upload, send := pipe.New()
	defer send.Close()
	reply, output := pipe.New(pipe.WithSizeLimit(0))
	defer reply.Interrupt()
	sink := &takenWriter{Writer: output, taken: make(chan struct{})}

	// More than the uplink holds, so that the upload is still being
	// written when the carrier fails.
	var first buf.MultiBuffer
	for size := 0; size < 256*1024; size += buf.Size {
		block := buf.New()
		block.Extend(buf.Size)
		if target.Network == net.Network_UDP {
			block.UDP = &target
		}
		first = append(first, block)
	}
	if err := send.WriteMultiBuffer(first); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	defer close(stop)
	returned := make(chan error, 1)
	failure := errors.New("connection reset")
	carrier := carrierFunc(func(link *transport.Link) (result error) {
		defer func() { returned <- result }()
		reader := &buf.BufferedReader{Reader: link.Reader}
		defer func() { buf.ReleaseMulti(reader.Buffer) }()
		var opening FrameMetadata
		if err := opening.Unmarshal(reader, false); err != nil {
			return err
		}
		if opening.SessionStatus != SessionStatusNew || !opening.Option.Has(OptionData) {
			return fmt.Errorf("expected a NEW with payload, got %+v", opening)
		}
		if err := buf.Copy(NewStreamReader(reader), buf.Discard); err != nil {
			return err
		}
		response := NewResponseWriter(opening.SessionID, link.Writer, protocol.TransferTypeStream)
		for i, text := range []string{"first", "last"} {
			block := buf.New()
			if _, err := block.WriteString(text); err != nil {
				block.Release()
				return err
			}
			if err := response.WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
				return err
			}
			if i == 0 {
				// The application's pipe holds one frame and it is not
				// reading: the worker is held on the second.
				select {
				case <-sink.taken:
				case <-stop:
					return errors.New("the test ended before the first frame was delivered")
				}
			}
		}
		if err := response.Close(); err != nil {
			return err
		}
		return failure
	})
	worker, err := (&DialingWorkerFactory{Proxy: carrier}).Create()
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	carrierGone := make(chan struct{})
	releaseUplink := sync.OnceFunc(func() { close(carrierGone) })
	defer releaseUplink()
	if openingAlone {
		worker.link.Writer = &openingOnly{MutexWriter: worker.link.Writer.(*MutexWriter), release: carrierGone}
	}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
		t.Fatal("the worker refused the session")
	}
	if err := await(t, returned, "the carrier to return"); !errors.Is(err, failure) {
		t.Fatalf("the carrier returned %v", err)
	}
	await(t, worker.WaitClosed(), "the worker to close")
	releaseUplink()
	// The rest of the upload has been refused.
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
}

// A session whose opening frame the uplink refused has no reply to wait for:
// the carrier never saw it. It is closed at once, also while another
// session's slow reader holds the worker's reader.
func TestDialingWorkerEndsASessionWhoseOpeningFrameIsRefused(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		target := net.TCPDestination(net.LocalHostIP, 80)
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
		slowUpload, slowSend := pipe.New(pipe.WithSizeLimit(0))
		defer slowSend.Close()
		slowReply, slowOutput := pipe.New(pipe.WithSizeLimit(0))
		defer slowReply.Interrupt()
		slowSink := &takenWriter{Writer: slowOutput, taken: make(chan struct{})}

		fail := make(chan struct{})
		letFail := sync.OnceFunc(func() { close(fail) })
		defer letFail()
		failure := errors.New("connection reset")
		carrier := carrierFunc(func(link *transport.Link) error {
			reader := &buf.BufferedReader{Reader: link.Reader}
			defer func() { buf.ReleaseMulti(reader.Buffer) }()
			var opening FrameMetadata
			if err := opening.Unmarshal(reader, false); err != nil {
				return err
			}
			response := NewResponseWriter(opening.SessionID, link.Writer, protocol.TransferTypeStream)
			for range 2 {
				block := buf.New()
				block.Extend(buf.Size)
				if err := response.WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
					return err
				}
			}
			<-fail
			return failure
		})
		worker, err := (&DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		if !worker.Dispatch(ctx, &transport.Link{Reader: slowUpload, Writer: slowSink}) {
			t.Fatal("the worker refused the first session")
		}
		// The slow application's pipe holds one frame of its reply and the
		// worker's reader is held on the next.
		await(t, slowSink.taken, "the first frame of the slow session's reply")
		synctest.Wait()

		// The second session is dispatched and the carrier fails before the
		// session has sent the frame that opens it.
		upload, send := pipe.New(pipe.WithSizeLimit(0))
		defer send.Close()
		reply, output := pipe.New(pipe.WithSizeLimit(0))
		defer reply.Interrupt()
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: output}) {
			t.Fatal("the worker refused the second session")
		}
		letFail()
		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 2 {
			t.Fatalf("%d sessions before the opening frame was sent, want 2", active)
		}

		// With nothing to upload the session opens itself after a wait.
		time.Sleep(time.Second)
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 1 {
			t.Fatalf("%d sessions after the opening frame was refused, want the slow one only", active)
		}
		data, err := reply.ReadMultiBufferTimeout(time.Second)
		buf.ReleaseMulti(data)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("the session's reply did not end: %v", err)
		}
	})
}

// On a worker that is not closed a refused upload still ends its session at
// once: only a closed worker keeps one for its reply.
func TestClientWorkerEndsASessionWhoseUploadIsRefusedWhileOpen(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		carrier := carrierFunc(func(*transport.Link) error {
			<-release
			return nil
		})
		worker, err := (&DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()

		upload, send := pipe.New(pipe.WithSizeLimit(0))
		defer send.Close()
		reply, output := pipe.New(pipe.WithSizeLimit(0))
		defer reply.Interrupt()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: output}) {
			t.Fatal("the worker refused the session")
		}
		sendBlock := func() {
			block := buf.New()
			block.Extend(buf.Size)
			if err := send.WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
				t.Fatal(err)
			}
		}
		sendBlock()
		synctest.Wait()

		// The carrier stops taking the upload and has not returned.
		worker.link.Writer.(interface{ Interrupt() }).Interrupt()
		sendBlock()
		synctest.Wait()
		if worker.Closed() {
			t.Fatal("the worker closed under a live carrier")
		}
		if active := worker.ActiveConnections(); active != 0 {
			t.Fatalf("%d sessions after the upload was refused, want none", active)
		}
	})
}
