package mux_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// A worker serializes its writes through mux.MutexWriter (upstream
// 5745dea2). When the worker ends it must still interrupt the writer it was
// given: otherwise the peer reading that pipe, such as an inbound copying the
// response to its connection, waits until its own timeout.
func TestWorkerEndInterruptsWrappedWriter(t *testing.T) {
	for _, side := range []string{"server", "client"} {
		t.Run(side, func(t *testing.T) {
			inReader, inWriter := pipe.New(pipe.WithoutSizeLimit())
			outReader, outWriter := pipe.New(pipe.WithoutSizeLimit())
			link := transport.Link{Reader: inReader, Writer: outWriter}

			var closed <-chan struct{}
			switch side {
			case "server":
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
				worker, err := mux.NewServerWorker(ctx, noopDispatcher{}, &link)
				if err != nil {
					t.Fatal(err)
				}
				closed = worker.WaitClosed()
			case "client":
				worker, err := mux.NewClientWorker(link, mux.ClientStrategy{})
				if err != nil {
					t.Fatal(err)
				}
				closed = worker.WaitClosed()
			}

			inWriter.Close()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not end after its input closed")
			}

			read := make(chan error, 1)
			go func() {
				mb, err := outReader.ReadMultiBuffer()
				buf.ReleaseMulti(mb)
				read <- err
			}()
			select {
			case err := <-read:
				if err == nil {
					t.Fatal("read data from an ended worker, want the pipe closed")
				}
			case <-time.After(5 * time.Second):
				outReader.Interrupt()
				t.Fatal("the writer the worker was given is still open after the worker ended")
			}
		})
	}
}
