package singbridge

import (
	"context"
	"io"
	stdnet "net"
	"sync"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

func CopyPacketConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, destination net.Destination, serverConn net.PacketConn) error {
	cancel := func() {
		common.Interrupt(link.Reader)
		common.Interrupt(serverConn)
	}
	conn := &PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
		Conn:   inboundConn,
		T:      signal.CancelAfterInactivity(ctx, cancel, 300*time.Second),
	}
	return ReturnError(bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(serverConn)))
}

type PacketConnWrapper struct {
	buf.Reader
	buf.Writer
	net.Conn
	Dest net.Destination

	// cacheMu protects cached buffer ownership against concurrent Close.
	cacheMu sync.Mutex
	cached  buf.MultiBuffer
	readErr error
	closed  bool

	// A simple patch to avoid goroutine leak since sing infra cannot awake read block by write err
	T *signal.ActivityTimer
}

func (w *PacketConnWrapper) ReadPacket(buffer *B.Buffer) (addr M.Socksaddr, err error) {
	w.T.Update()
	defer func() {
		if err != nil {
			// uplinkonly
			w.T.SetTimeout(2 * time.Second)
		}
	}()
	w.cacheMu.Lock()
	defer w.cacheMu.Unlock()
	for {
		if w.closed {
			return M.Socksaddr{}, stdnet.ErrClosed
		}
		if len(w.cached) != 0 {
			var packet *buf.Buffer
			w.cached, packet = buf.SplitFirst(w.cached)
			if packet == nil {
				continue
			}
			defer packet.Release()
			n, err := buffer.Write(packet.Bytes())
			if err != nil {
				return M.Socksaddr{}, err
			}
			if n != int(packet.Len()) {
				return M.Socksaddr{}, io.ErrShortBuffer
			}
			destination := w.Dest
			if packet.UDP != nil {
				destination = *packet.UDP
			}
			return ToSocksaddr(destination), nil
		}
		if w.readErr != nil {
			return M.Socksaddr{}, w.readErr
		}

		// A blocking read must not prevent Close from releasing cached packets.
		w.cacheMu.Unlock()
		mb, readErr := w.ReadMultiBuffer()
		w.cacheMu.Lock()
		if w.closed {
			buf.ReleaseMulti(mb)
			return M.Socksaddr{}, stdnet.ErrClosed
		}
		w.cached, w.readErr = mb, readErr
	}
}

func (w *PacketConnWrapper) WritePacket(buffer *B.Buffer, destination M.Socksaddr) (err error) {
	w.T.Update()
	defer func() {
		if err != nil {
			// downlinkonly
			w.T.SetTimeout(5 * time.Second)
		}
	}()
	endpoint, err := ToDestination(destination, net.Network_UDP)
	if err != nil {
		return err
	}
	vBuf := buf.New()
	vBuf.Write(buffer.Bytes())
	vBuf.UDP = &endpoint
	return w.WriteMultiBuffer(buf.MultiBuffer{vBuf})
}

func (w *PacketConnWrapper) Close() error {
	w.cacheMu.Lock()
	defer w.cacheMu.Unlock()
	w.closed = true
	buf.ReleaseMulti(w.cached)
	w.cached = nil
	return nil
}
