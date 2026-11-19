package mux

// What fetchInput does after a first payload stops, where the tests beside
// this file reach the same lines from an upload that got past it.

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
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// heldRecord holds the first log record that contains text.
type heldRecord struct {
	text    string
	once    *sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (h heldRecord) Handle(message log.Message) {
	if strings.Contains(message.String(), h.text) {
		h.once.Do(func() { close(h.entered) })
		<-h.resume
	}
}

// slowSessionCarrier answers the worker's first session with two frames, so
// that the worker's reader is held on the second by an application that does
// not read, and fails once released.
func slowSessionCarrier(fail <-chan struct{}) carrierFunc {
	return func(link *transport.Link) error {
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
		return errors.New("connection reset")
	}
}

func uploadBlocks(count int) buf.MultiBuffer {
	var blocks buf.MultiBuffer
	for range count {
		block := buf.New()
		block.Extend(buf.Size)
		blocks = append(blocks, block)
	}
	return blocks
}

// A first payload cut by a refusal after its opening frame, on an open
// worker, ends its session also when the carrier returns while that refusal
// is being reported.
// TestDialingWorkerEndsASessionRefusedWhileOpenThoughItsCarrierReturnsMeanwhile
// holds the report of an upload after the first payload.
func TestDialingWorkerEndsASessionWhoseFirstPayloadIsRefusedWhileOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		report := heldRecord{text: "failed to write first payload", once: new(sync.Once), entered: make(chan struct{}), resume: make(chan struct{})}
		log.RegisterHandler(report)
		release := sync.OnceFunc(func() { close(report.resume) })
		defer release()
		defer log.RegisterHandler(discardRecords{})

		target := net.TCPDestination(net.LocalHostIP, 80)
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
		fail := make(chan struct{})
		letFail := sync.OnceFunc(func() { close(fail) })
		defer letFail()
		worker, err := (&DialingWorkerFactory{Proxy: slowSessionCarrier(fail)}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()

		slowUpload, slowSend := pipe.New(pipe.WithSizeLimit(0))
		defer slowSend.Close()
		slowReply, slowOutput := pipe.New(pipe.WithSizeLimit(0))
		defer slowReply.Interrupt()
		slowSink := &takenWriter{Writer: slowOutput, taken: make(chan struct{})}
		if !worker.Dispatch(ctx, &transport.Link{Reader: slowUpload, Writer: slowSink}) {
			t.Fatal("the worker refused the first session")
		}
		await(t, slowSink.taken, "the first frame of the slow session's reply")
		synctest.Wait()

		uplink := worker.link.Writer.(*MutexWriter)
		refusing := make(chan struct{})
		refuse := sync.OnceFunc(func() { close(refusing) })
		defer refuse()
		worker.link.Writer = &openingOnly{MutexWriter: uplink, release: refusing}
		upload, send := pipe.New(pipe.WithSizeLimit(0))
		defer send.Close()
		reply, output := pipe.New(pipe.WithSizeLimit(0))
		defer reply.Interrupt()
		// Two frames of one first payload: the second is held in front of
		// the uplink.
		if err := send.WriteMultiBuffer(uploadBlocks(2)); err != nil {
			t.Fatal(err)
		}
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: output}) {
			t.Fatal("the worker refused the second session")
		}
		synctest.Wait()

		// The carrier stops taking the upload and has not returned.
		uplink.Interrupt()
		refuse()
		await(t, report.entered, "the report of the refused first payload")
		if worker.Closed() {
			t.Fatal("the worker closed before the first payload was refused")
		}

		// The carrier returns while that report is held.
		letFail()
		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()
		release()
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 1 {
			t.Fatalf("%d sessions after the refused first payload was reported, want the slow one only", active)
		}
	})
}

// A first payload cut by a refusal after its opening frame on a closed worker
// is read on and dropped like any refused upload: its session is kept for
// the reply the carrier had written when the upload then runs to its end,
// and ended when its application leaves.
// TestDialingWorkerKeepsQueuedReplyWhenFirstUploadIsCutShort reads the reply
// and never ends the upload.
func TestDialingWorkerDropsTheRestOfACutFirstPayload(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	for name, leaves := range map[string]bool{"the upload ends": false, "the application leaves": true} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				target := net.TCPDestination(net.LocalHostIP, 80)
				ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
				fail := make(chan struct{})
				letFail := sync.OnceFunc(func() { close(fail) })
				defer letFail()
				worker, err := (&DialingWorkerFactory{Proxy: slowSessionCarrier(fail)}).Create()
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close()

				// The frame that opens the session reaches the carrier;
				// the next one of the same first payload is held in front
				// of the uplink until the carrier is gone.
				carrierGone := make(chan struct{})
				releaseUplink := sync.OnceFunc(func() { close(carrierGone) })
				defer releaseUplink()
				worker.link.Writer = &openingOnly{MutexWriter: worker.link.Writer.(*MutexWriter), release: carrierGone}
				upload, send := pipe.New(pipe.WithSizeLimit(0))
				defer send.Close()
				reply, output := pipe.New(pipe.WithSizeLimit(0))
				defer reply.Interrupt()
				sink := &takenWriter{Writer: output, taken: make(chan struct{})}
				if err := send.WriteMultiBuffer(uploadBlocks(2)); err != nil {
					t.Fatal(err)
				}
				if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
					t.Fatal("the worker refused the session")
				}
				// The application reads nothing: the first frame of its
				// reply fills its pipe and the reader is held on the second.
				await(t, sink.taken, "the first frame of the reply")
				synctest.Wait()
				letFail()
				await(t, worker.WaitClosed(), "the worker to close")
				synctest.Wait()
				releaseUplink()
				synctest.Wait()
				if active := worker.ActiveConnections(); active != 1 {
					t.Fatalf("%d sessions after the first payload was cut, want the one whose reply waits", active)
				}

				want, wantReply := uint32(1), 2*buf.Size
				if leaves {
					upload.Interrupt()
					want, wantReply = 0, buf.Size
				} else if err := send.Close(); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if active := worker.ActiveConnections(); active != want {
					t.Fatalf("%d sessions, want %d", active, want)
				}
				var got int
				for {
					data, err := reply.ReadMultiBufferTimeout(time.Second)
					got += int(data.Len())
					buf.ReleaseMulti(data)
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						t.Fatalf("read %d bytes of the reply, then: %v", got, err)
					}
				}
				if got != wantReply {
					t.Fatalf("the application read %d bytes of its reply, want %d", got, wantReply)
				}
			})
		})
	}
}

// failingFirstRead is an input whose first, timed read fails.
type failingFirstRead struct{}

func (failingFirstRead) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, errors.New("read deadline")
}

func (failingFirstRead) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return nil, errors.New("read deadline")
}

// The END of a session whose first read failed carries the error flag, on a
// live worker, as on main.
// TestClientWorkerSendsTheLastBatchAndMarksAFailedUpload has its input fail
// after the first payload.
func TestClientWorkerMarksTheEndAfterAFailedFirstRead(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		uplink, uplinkWriter := pipe.New()
		defer uplink.Interrupt()
		downlink, downlinkWriter := pipe.New()
		defer downlinkWriter.Close()
		worker, err := NewClientWorker(transport.Link{Reader: downlink, Writer: uplinkWriter}, ClientStrategy{})
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		reply, output := pipe.New()
		defer reply.Interrupt()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: failingFirstRead{}, Writer: output}) {
			t.Fatal("the worker refused the session")
		}
		synctest.Wait()
		frames := &buf.BufferedReader{Reader: uplink}
		defer func() { buf.ReleaseMulti(frames.Buffer) }()
		var frame FrameMetadata
		if err := frame.Unmarshal(frames, false); err != nil {
			t.Fatal(err)
		}
		if frame.SessionStatus != SessionStatusEnd || !frame.Option.Has(OptionError) {
			t.Fatalf("the frame is %+v, want an END marked as failed", frame)
		}
	})
}
