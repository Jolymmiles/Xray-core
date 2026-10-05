package mux_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func newLinkPair() (*transport.Link, *transport.Link) {
	opt := pipe.WithoutSizeLimit()
	uplinkReader, uplinkWriter := pipe.New(opt)
	downlinkReader, downlinkWriter := pipe.New(opt)

	uplink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	downlink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	return uplink, downlink
}

type TestDispatcher struct {
	OnDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *TestDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.OnDispatch(ctx, dest)
}

func (d *TestDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	return nil
}

func (d *TestDispatcher) Start() error {
	return nil
}

func (d *TestDispatcher) Close() error {
	return nil
}

func (*TestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestRegressionOutboundLeak(t *testing.T) {
	originalOutbounds := []*session.Outbound{{}}
	serverCtx := session.ContextWithOutbounds(context.Background(), originalOutbounds)

	websiteUplink, websiteDownlink := newLinkPair()

	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			// emulate what DefaultRouter.Dispatch does, and mutate something on the context
			ob := session.OutboundsFromContext(ctx)[0]
			ob.Target = dest
			return websiteDownlink, nil
		},
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	_, err := mux.NewServerWorker(serverCtx, &dispatcher, muxServerUplink)
	common.Must(err)

	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	common.Must(err)

	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})

	muxClientUplink, muxClientDownlink := newLinkPair()

	ok := client.Dispatch(clientCtx, muxClientUplink)
	if !ok {
		t.Error("failed to dispatch")
	}

	{
		b := buf.FromBytes([]byte("hello"))
		common.Must(muxClientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err := websiteUplink.Reader.ReadMultiBuffer()
	common.Must(err)
	res := resMb.String()
	if res != "hello" {
		t.Error("upload: ", res)
	}

	{
		b := buf.FromBytes([]byte("world"))
		common.Must(websiteUplink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err = muxClientDownlink.Reader.ReadMultiBuffer()
	common.Must(err)
	res = resMb.String()
	if res != "world" {
		t.Error("download: ", res)
	}

	outbounds := session.OutboundsFromContext(serverCtx)
	if outbounds[0] != originalOutbounds[0] {
		t.Error("outbound got reassigned: ", outbounds[0])
	}

	if outbounds[0].Target.Address != nil {
		t.Error("outbound target got leaked: ", outbounds[0].Target.String())
	}
}

// keepAliveConn asks for a KeepAlive and reports its downlink as long silent,
// so that a worker pokes it at once.
type keepAliveConn struct {
	net.Conn
	bytesFrom, bytesTo int32
}

func (c keepAliveConn) MuxKeepAlive() (int32, int32)      { return 1, 1 }
func (c keepAliveConn) MuxKeepAliveBytes() (int32, int32) { return c.bytesFrom, c.bytesTo }
func (c keepAliveConn) DownlinkIdle() time.Duration       { return time.Hour }

func TestServerWorkerKeepAlive(t *testing.T) {
	for _, padding := range [][2]int32{{0, 0}, {50, 400}, {10000, 20000}} {
		uplink, downlink := newLinkPair()
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
			Conn: keepAliveConn{bytesFrom: padding[0], bytesTo: padding[1]},
		})
		worker, err := mux.NewServerWorker(ctx, &TestDispatcher{}, uplink)
		common.Must(err)
		defer worker.Close()

		mb, err := downlink.Reader.ReadMultiBuffer()
		common.Must(err)
		if mb.Len() > buf.Size {
			t.Fatal(padding, " frame does not fit one buffer: ", mb.Len())
		}

		reader := &buf.MultiBufferContainer{MultiBuffer: mb}
		var meta mux.FrameMetadata
		common.Must(meta.Unmarshal(reader, false))
		if meta.SessionStatus != mux.SessionStatusKeepAlive {
			t.Fatal(padding, " unexpected status: ", meta.SessionStatus)
		}
		if got := meta.Option.Has(mux.OptionData); got != (padding[1] > 0) {
			t.Fatal(padding, " unexpected data flag: ", got)
		}
	}
}

// busyConn asks for a KeepAlive but never reports its downlink as silent, and
// tells each time the worker checks.
type busyConn struct {
	net.Conn
	checked chan struct{}
}

func (c busyConn) MuxKeepAlive() (int32, int32)      { return 1, 1 }
func (c busyConn) MuxKeepAliveBytes() (int32, int32) { return 0, 0 }
func (c busyConn) DownlinkIdle() time.Duration {
	select {
	case c.checked <- struct{}{}:
	default:
	}
	return 0
}

func TestServerWorkerKeepAliveStopsWithWorker(t *testing.T) {
	uplink, _ := newLinkPair()
	conn := busyConn{checked: make(chan struct{}, 1)}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: conn})
	worker, err := mux.NewServerWorker(ctx, &TestDispatcher{}, uplink)
	common.Must(err)

	<-conn.checked
	common.Must(worker.Close())
	select {
	case <-conn.checked: // a check that was already under way
	default:
	}
	select {
	case <-conn.checked:
		t.Fatal("KeepAlive loop still runs after the worker closed")
	case <-time.After(2500 * time.Millisecond):
	}
}

// pausedConn reports its downlink as long silent, but holds each check until
// the test releases it, so that a test can close the worker in between.
type pausedConn struct {
	net.Conn
	checking chan struct{}
	resume   chan struct{}
}

func (c pausedConn) MuxKeepAlive() (int32, int32)      { return 1, 1 }
func (c pausedConn) MuxKeepAliveBytes() (int32, int32) { return 0, 0 }
func (c pausedConn) DownlinkIdle() time.Duration {
	c.checking <- struct{}{}
	<-c.resume
	return time.Hour
}

// linkWriter accepts writes the way a VLESS link writer does: it cannot be
// interrupted. With writing set, it holds each write until release closes.
type linkWriter struct {
	writes  atomic.Int32
	writing chan struct{}
	release chan struct{}
}

func (w *linkWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	w.writes.Add(1)
	if w.writing != nil {
		w.writing <- struct{}{}
		<-w.release
	}
	return nil
}

// idleReader is an uplink that sends nothing and, like a connection, keeps
// reading through Interrupt; the test ends it by closing eof.
type idleReader struct{ eof chan struct{} }

func (r idleReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.eof
	return nil, io.EOF
}

// discardLogs handles records in place. The default logger starts a goroutine
// that waits on channels created outside a synctest bubble.
type discardLogs struct{}

func (discardLogs) Handle(log.Message) {}

// A worker that is closing must not get a KeepAlive frame, even when the
// loop was already checking the downlink as Close began.
func TestServerWorkerKeepAliveSkipsClosingWorker(t *testing.T) {
	log.RegisterHandler(discardLogs{})
	synctest.Test(t, func(t *testing.T) {
		reader := idleReader{eof: make(chan struct{})}
		defer close(reader.eof)
		writer := &linkWriter{}
		conn := pausedConn{checking: make(chan struct{}), resume: make(chan struct{})}
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: conn})
		worker, err := mux.NewServerWorker(ctx, &TestDispatcher{}, &transport.Link{Reader: reader, Writer: writer})
		common.Must(err)

		<-conn.checking
		go worker.Close()
		synctest.Wait()
		close(conn.resume)
		<-worker.WaitClosed()
		synctest.Wait()
		if n := writer.writes.Load(); n != 0 {
			t.Fatalf("KeepAlive wrote %d frame(s) to a worker that was closing", n)
		}
	})
}

// Close must not wait for a KeepAlive write stuck on a link it cannot
// interrupt, such as a VLESS writer whose client stopped reading: shutdown
// would then last as long as the stalled connection.
func TestServerWorkerCloseDoesNotWaitForStuckKeepAliveWrite(t *testing.T) {
	log.RegisterHandler(discardLogs{})
	synctest.Test(t, func(t *testing.T) {
		reader := idleReader{eof: make(chan struct{})}
		defer close(reader.eof)
		writer := &linkWriter{writing: make(chan struct{}), release: make(chan struct{})}
		defer close(writer.release)
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: keepAliveConn{}})
		worker, err := mux.NewServerWorker(ctx, &TestDispatcher{}, &transport.Link{Reader: reader, Writer: writer})
		common.Must(err)

		<-writer.writing
		go worker.Close()
		synctest.Wait()
		if !worker.Closed() {
			t.Error("Close is still waiting for a KeepAlive write stuck on the link")
		}
	})
}

func TestClientWorkerSkipsKeepAlivePadding(t *testing.T) {
	upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
	downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())
	worker, err := mux.NewClientWorker(transport.Link{Reader: downReader, Writer: upWriter}, mux.ClientStrategy{})
	common.Must(err)
	defer worker.Close()

	appReader, appWriter := pipe.New(pipe.WithoutSizeLimit())
	respReader, respWriter := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: appReader, Writer: respWriter}) {
		t.Fatal("dispatch failed")
	}
	common.Must(appWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hi"))}))

	var opened mux.FrameMetadata
	common.Must(opened.Unmarshal(&buf.BufferedReader{Reader: upReader}, false))
	if opened.SessionStatus != mux.SessionStatusNew {
		t.Fatal("unexpected first frame: ", opened.SessionStatus)
	}

	// Padding as the server sends it, followed by data for the open session.
	for _, padding := range []int{1, 300, 1024} {
		b := buf.New()
		meta := mux.FrameMetadata{SessionStatus: mux.SessionStatusKeepAlive}
		meta.Option.Set(mux.OptionData)
		common.Must(meta.WriteTo(b))
		common.Must2(serial.WriteUint16(b, uint16(padding)))
		common.Must2(rand.Read(b.Extend(int32(padding))))
		common.Must(downWriter.WriteMultiBuffer(buf.MultiBuffer{b}))
	}
	data := mux.NewResponseWriter(opened.SessionID, downWriter, protocol.TransferTypeStream)
	common.Must(data.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}))

	mb, err := respReader.ReadMultiBuffer()
	common.Must(err)
	got := make([]byte, mb.Len())
	mb.Copy(got)
	buf.ReleaseMulti(mb)
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("session got %q after KeepAlive padding, want %q", got, "hello")
	}
}
