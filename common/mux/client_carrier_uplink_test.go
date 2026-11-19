package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

// carrierFunc is an outbound whose carrier is the function.
type carrierFunc func(*transport.Link) error

func (f carrierFunc) Process(_ context.Context, link *transport.Link, _ internet.Dialer) error {
	return f(link)
}

// A reply for a session the application has closed makes the worker answer
// with an END on the uplink. When the carrier has failed nobody reads the
// uplink; if it is full that write must not hold the worker's reader, or the
// sessions behind it never get their replies and their end. The uplink is
// filled here after the carrier's last read, and without that as a control.
func TestDialingWorkerDrainsPastAFullUplinkWhenCarrierFails(t *testing.T) {
	for _, full := range []bool{false, true} {
		for _, fails := range []bool{true, false} {
			t.Run(fmt.Sprintf("full=%t/fails=%t", full, fails), func(t *testing.T) {
				drainsPastAFullUplink(t, full, fails)
			})
		}
	}
}

// drainsPastAFullUplink has the carrier return an error, or none with the
// downlink left open: the uplink is no more read in either case.
func drainsPastAFullUplink(t *testing.T, full, fails bool) {
	const deadline = 3 * time.Second
	{
		{
			firstID := make(chan uint16, 1)
			secondNew := make(chan struct{})
			uplinkReadDone := make(chan struct{})
			send := make(chan struct{})
			release := sync.OnceFunc(func() { close(send) })
			processResult := make(chan error, 1)
			var carrierFailure error
			if fails {
				carrierFailure = errors.New("carrier failed after queuing responses")
			}
			carrier := carrierFunc(func(link *transport.Link) (result error) {
				defer func() { processResult <- result }()
				reader := &buf.BufferedReader{Reader: link.Reader}
				defer func() { buf.ReleaseMulti(reader.Buffer) }()
				var ids [2]uint16
				for i := range ids {
					var frame FrameMetadata
					if err := frame.Unmarshal(reader, false); err != nil {
						return err
					}
					if frame.SessionStatus != SessionStatusNew || frame.Option.Has(OptionData) {
						return fmt.Errorf("expected a NEW without payload, got %+v", frame)
					}
					ids[i] = frame.SessionID
					if i == 0 {
						firstID <- ids[0]
					}
				}
				close(secondNew)
				var end FrameMetadata
				if err := end.Unmarshal(reader, false); err != nil {
					return err
				}
				if end.SessionStatus != SessionStatusEnd || end.SessionID != ids[0] {
					return fmt.Errorf("expected a local END for %d, got %+v", ids[0], end)
				}
				close(uplinkReadDone)
				<-send // The carrier has completed its last uplink read.
				for i, payload := range []string{"late reply", "sibling reply"} {
					response := NewResponseWriter(ids[i], link.Writer, protocol.TransferTypeStream)
					buffer := buf.New()
					if _, err := buffer.WriteString(payload); err != nil {
						buffer.Release()
						return err
					}
					if err := response.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
						return err
					}
					if i == 1 {
						if err := response.Close(); err != nil {
							return err
						}
					}
				}
				return carrierFailure
			})
			worker, err := (&DialingWorkerFactory{Proxy: carrier}).Create()
			if err != nil {
				t.Fatal(err)
			}
			defer worker.Close()
			defer release()
			dispatch := func() *pipe.Reader {
				input, inputWriter := pipe.New()
				reader, output := pipe.New()
				t.Cleanup(func() { _ = inputWriter.Close(); reader.Interrupt() })
				ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
					Target: net.TCPDestination(net.LocalHostIP, 80),
				}})
				if !worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: output}) {
					t.Fatal("worker refused session")
				}
				return reader
			}
			dispatch()
			var id uint16
			select {
			case id = <-firstID:
			case <-time.After(deadline):
				t.Fatal("carrier did not read first NEW")
			}
			sibling := dispatch()
			select {
			case <-secondNew:
			case err := <-processResult:
				t.Fatalf("carrier exited early: %v", err)
			case <-time.After(deadline):
				t.Fatal("carrier did not read second NEW")
			}
			local, ok := worker.sessionManager.active(id)
			if !ok {
				t.Fatal("first session missing before local close")
			}
			if err := local.Close(false); err != nil {
				t.Fatal(err)
			}
			select {
			case <-uplinkReadDone:
			case err := <-processResult:
				t.Fatalf("carrier exited early: %v", err)
			case <-time.After(deadline):
				t.Fatal("carrier did not consume both NEWs and local END")
			}
			if full {
				// Inject the backlog after the carrier's last read. The real
				// pipe considers an existing queue over 64 KiB full.
				var backlog buf.MultiBuffer
				for bytes := 0; bytes <= 64*1024; bytes += buf.Size {
					block := buf.New()
					block.Extend(buf.Size)
					backlog = append(backlog, block)
				}
				if err := worker.link.Writer.WriteMultiBuffer(backlog); err != nil {
					t.Fatal(err)
				}
			}
			release()
			select {
			case <-worker.WaitClosed():
			case <-time.After(deadline):
				t.Fatal("factory did not observe the carrier return")
			}
			if err := <-processResult; !errors.Is(err, carrierFailure) {
				t.Fatalf("carrier returned %v", err)
			}

			data, err := sibling.ReadMultiBufferTimeout(deadline)
			defer buf.ReleaseMulti(data)
			if err != nil || data.String() != "sibling reply" {
				t.Fatalf("sibling read %q (%v), want complete reply", data.String(), err)
			}
			tail, err := sibling.ReadMultiBufferTimeout(deadline)
			buf.ReleaseMulti(tail)
			if !errors.Is(err, io.EOF) {
				t.Fatalf("sibling did not end: %v", err)
			}
		}
	}
}
