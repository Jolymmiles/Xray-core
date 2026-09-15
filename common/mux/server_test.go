package mux_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
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
