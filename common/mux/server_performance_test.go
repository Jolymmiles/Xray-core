package mux_test

import (
	"context"
	"io"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type benchDispatcher struct{}

func (benchDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}

func (benchDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}
func (benchDispatcher) Start() error      { return nil }
func (benchDispatcher) Close() error      { return nil }
func (benchDispatcher) Type() interface{} { return routing.DispatcherType() }

// BenchmarkServerWorkerFinishLifecycle measures NewServerWorker → EOF → finish()
// (Interrupt then done.Close) with a VLESS-style pooled link reader.
func BenchmarkServerWorkerFinishLifecycle(b *testing.B) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
	dispatcher := benchDispatcher{}

	b.ReportAllocs()
	for b.Loop() {
		server, client := stdnet.Pipe()
		pooled := buf.NewPooledBufferedReader(buf.NewPooledReader(server), nil)
		link := &transport.Link{
			Reader: pooled,
			Writer: buf.Discard,
		}
		worker, err := mux.NewServerWorker(ctx, dispatcher, link)
		if err != nil {
			b.Fatal(err)
		}
		_ = client.Close()
		_ = server.Close()
		<-worker.WaitClosed()
		pooled.Release()
	}
}

// BenchmarkServerWorkerCloseIdempotent measures finishOnce when Close is called
// after the worker has already finished (common DispatchLink/ctx cancel path).
func BenchmarkServerWorkerCloseIdempotent(b *testing.B) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
	dispatcher := benchDispatcher{}

	server, client := stdnet.Pipe()
	b.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	pooled := buf.NewPooledBufferedReader(buf.NewPooledReader(server), nil)
	link := &transport.Link{Reader: pooled, Writer: buf.Discard}
	worker, err := mux.NewServerWorker(ctx, dispatcher, link)
	if err != nil {
		b.Fatal(err)
	}
	_ = client.Close()
	_ = server.Close()
	<-worker.WaitClosed()

	b.ReportAllocs()
	for b.Loop() {
		_ = worker.Close()
	}
	pooled.Release()
}

// repeatedFrames yields the same Mux.Cool frame a fixed number of times, then
// io.EOF, without materializing the whole stream.
type repeatedFrames struct {
	frame  []byte
	offset int
	left   int
}

func (r *repeatedFrames) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) && r.left > 0 {
		copied := copy(p[n:], r.frame[r.offset:])
		n += copied
		r.offset += copied
		if r.offset == len(r.frame) {
			r.offset = 0
			r.left--
		}
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// BenchmarkServerWorkerKeepAliveFrames measures the per-frame cost of a
// ServerWorker reading KeepAlive frames: one op is one frame.
func BenchmarkServerWorkerKeepAliveFrames(b *testing.B) {
	frame := buf.New()
	defer frame.Release()
	meta := mux.FrameMetadata{SessionStatus: mux.SessionStatusKeepAlive}
	if err := meta.WriteTo(frame); err != nil {
		b.Fatal(err)
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
	link := &transport.Link{
		Reader: buf.NewReader(&repeatedFrames{frame: frame.Bytes(), left: b.N}),
		Writer: buf.Discard,
	}

	b.ReportAllocs()
	b.ResetTimer()
	worker, err := mux.NewServerWorker(ctx, benchDispatcher{}, link)
	if err != nil {
		b.Fatal(err)
	}
	<-worker.WaitClosed()
}
