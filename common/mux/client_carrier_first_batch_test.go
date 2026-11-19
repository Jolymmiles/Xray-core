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

// The first thing a session uploads goes out as one frame that opens the
// session and as many more as its size needs. A carrier that took the
// opening frame, answered in full and then failed leaves the rest of that
// upload refused; the application still gets the reply. Stream and packet
// sessions split their upload differently and both do.
func TestDialingWorkerKeepsQueuedReplyWhenFirstUploadIsCutShort(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	for _, target := range []net.Destination{
		net.TCPDestination(net.LocalHostIP, 80),
		net.UDPDestination(net.LocalHostIP, 53),
	} {
		t.Run(target.Network.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { keepsReplyOfCutFirstUpload(t, target) })
		})
	}
}

func keepsReplyOfCutFirstUpload(t *testing.T, target net.Destination) {
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

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
		t.Fatal("the worker refused the session")
	}
	if err := <-returned; !errors.Is(err, failure) {
		t.Fatalf("the carrier returned %v", err)
	}
	<-worker.WaitClosed()
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
