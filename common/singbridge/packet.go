package singbridge

import (
	"context"
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

	// cachedMu guards cached and closed, which ReadPacket and Close reach from
	// different goroutines.
	//
	// sing's task.Group runs its cleanup -- common.Close on both ends, so this
	// type's Close -- as soon as the group's context is done, and only THEN
	// waits for the tasks to return (task.go:115 before task.go:119). So Close
	// runs while the download task is still inside ReadPacket, every time a
	// session is cancelled or the upload direction fast-fails. Without this
	// lock, Close releases the very buffer ReadPacket is copying out of:
	// Buffer.Release stores v = nil before Clear() resets start/end, so the
	// racing Bytes() can slice a nil array to the old length and hand memmove
	// a source address of about zero. That is the pl-warsaw SIGSEGV, and the
	// interleavings that do not crash are worse -- they copy out of a 2 KiB
	// array already handed back to the pool and being refilled by another
	// session.
	cachedMu sync.Mutex
	cached   buf.MultiBuffer
	closed   bool

	// A simple patch to avoid goroutine leak since sing infra cannot awake read block by write err
	T *signal.ActivityTimer
}

// takeCached copies the next already-read datagram into buffer and reports
// whether there was one. The copy happens under the lock on purpose: releasing
// the buffer afterwards is what makes it unsafe to touch outside.
func (w *PacketConnWrapper) takeCached(buffer *B.Buffer) (net.Destination, bool) {
	w.cachedMu.Lock()
	defer w.cachedMu.Unlock()

	mb, bb := buf.SplitFirst(w.cached)
	if bb == nil {
		w.cached = nil
		return net.Destination{}, false
	}
	buffer.Write(bb.Bytes())
	w.cached = mb
	destination := w.Dest
	if bb.UDP != nil {
		destination = *bb.UDP
	}
	bb.Release()
	return destination, true
}

// stashCached hands the rest of a multi-datagram read to the next ReadPacket.
//
// If Close already ran, the tail is released here instead. Close has walked the
// slice it found and will never look again, so storing into cached now would
// strand every buffer in mb until the GC noticed -- the pool would never see
// them back.
func (w *PacketConnWrapper) stashCached(mb buf.MultiBuffer) {
	w.cachedMu.Lock()
	defer w.cachedMu.Unlock()

	if w.closed {
		buf.ReleaseMulti(mb)
		return
	}
	w.cached = mb
}

func (w *PacketConnWrapper) ReadPacket(buffer *B.Buffer) (addr M.Socksaddr, err error) {
	w.T.Update()
	defer func() {
		if err != nil {
			// uplinkonly
			w.T.SetTimeout(2 * time.Second)
		}
	}()
	if destination, ok := w.takeCached(buffer); ok {
		return ToSocksaddr(destination), nil
	}
	mb, err := w.ReadMultiBuffer()
	nb, bb := buf.SplitFirst(mb)
	if bb == nil {
		return M.Socksaddr{}, nil
	}
	// bb came straight out of ReadMultiBuffer and is not reachable from cached,
	// so Close cannot release it and this needs no lock. Only the tail does.
	buffer.Write(bb.Bytes())
	destination := w.Dest
	if bb.UDP != nil {
		destination = *bb.UDP
	}
	bb.Release()
	w.stashCached(nb)
	return ToSocksaddr(destination), nil
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
	w.cachedMu.Lock()
	defer w.cachedMu.Unlock()

	w.closed = true
	buf.ReleaseMulti(w.cached)
	// Dropping the slice as well as releasing it keeps a second Close (sing
	// closes both ends of a group, and a caller may close again) from putting
	// the same arrays back into the pool twice.
	w.cached = nil
	return nil
}
