package mux

import (
	"context"
	stdnet "net"
	"testing"
	"testing/synctest"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// stalledVLESSWriter is the link writer a VLESS inbound hands to the mux
// server, over a client that stopped reading: a PrefixWriter over the
// connection. It has neither Interrupt nor Close, so a write blocks until the
// connection closes.
func stalledVLESSWriter(t *testing.T) (buf.Writer, func()) {
	t.Helper()
	server, client := stdnet.Pipe()
	writer, err := buf.NewPrefixWriter(buf.NewWriter(server), []byte{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	return writer, func() {
		_ = server.Close()
		_ = client.Close()
	}
}

func packet(payload string) buf.MultiBuffer {
	return buf.MultiBuffer{buf.FromBytes([]byte(payload))}
}

// Closing a response sink must not wait for a response write stuck on such a
// link: the connection closes only after the worker finishes.
func TestResponseSinkCloseDoesNotWaitForStuckWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writer, closeConnection := stalledVLESSWriter(t)
		defer closeConnection()
		runtime := newRuntime()
		sink := runtime.newResponseSink(writer)
		if !sink.enqueue(1, packet("stuck")) {
			t.Fatal("response enqueue failed")
		}
		synctest.Wait()
		queued := buf.New()
		queued.WriteString("queued")
		if !sink.enqueue(1, buf.MultiBuffer{queued}) {
			t.Fatal("second response enqueue failed")
		}

		closed := make(chan struct{})
		go func() {
			sink.close()
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("response sink close is waiting for a write stuck on the link")
		}
		if queued.Len() != 0 {
			t.Error("response queued behind the stuck write was not released")
		}
		closeConnection()
		<-sink.done
		_ = runtime.Close()
	})
}

// Server.Close closes the shared runtime, which closes every worker's sink. One
// client that stopped reading must not hold the whole mux server's shutdown.
func TestRuntimeCloseDoesNotWaitForStuckResponseWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writer, closeConnection := stalledVLESSWriter(t)
		defer closeConnection()
		runtime := newRuntime()
		sink := runtime.newResponseSink(writer)
		if !sink.enqueue(1, packet("stuck")) {
			t.Fatal("response enqueue failed")
		}
		synctest.Wait()

		closed := make(chan struct{})
		go func() {
			_ = runtime.Close()
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("runtime close is waiting for a response write stuck on one link")
		}
		closeConnection()
		<-sink.done
	})
}

// idleLinkReader is an uplink that sends nothing and, like a VLESS body
// reader, ignores Interrupt; the test ends it by closing eof.
type idleLinkReader struct{ eof chan struct{} }

func (r idleLinkReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.eof
	return nil, context.Canceled
}

type discardRecords struct{}

func (discardRecords) Handle(log.Message) {}

// Worker shutdown runs in DispatchLink's caller. A wait for the stuck write
// there is circular: the inbound closes the connection only after
// DispatchLink returns, and only that close ends the write.
func TestServerWorkerCloseDoesNotWaitForStuckXUDPResponse(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		runtime := newRuntime()
		defer runtime.Close()
		writer, closeConnection := stalledVLESSWriter(t)
		defer closeConnection()
		reader := idleLinkReader{eof: make(chan struct{})}
		defer close(reader.eof)
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
		worker, err := newServerWorker(ctx, nil, &transport.Link{Reader: reader, Writer: writer}, runtime, false)
		if err != nil {
			t.Fatal(err)
		}
		if !worker.responseSink.enqueue(1, packet("stuck")) {
			t.Fatal("response enqueue failed")
		}
		synctest.Wait()

		go worker.Close()
		synctest.Wait()
		if !worker.Closed() {
			t.Fatal("worker close is waiting for an XUDP response write stuck on the link")
		}
	})
}
