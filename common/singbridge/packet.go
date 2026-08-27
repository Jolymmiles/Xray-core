package singbridge

import (
	"context"
	"runtime/debug"
	"sync"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

// panicError turns a recovered panic into the error a sing copy task returns.
//
// The wrappers in this package do not run on goroutines this repository
// started: bufio.CopyPacketConn and bufio.CopyConn hand each direction to
// sing's task.Group, and the Shadowsocks-2022 UDP path enters
// NewPacketConnection from a goroutine sing/common/udpnat spawns per NAT
// entry. Nothing on the way in recovers either -- app/proxyman/inbound calls
// proxy.Process bare in this tree -- so a panic here ends the process rather
// than the session. Returning an error instead fails one task, which
// fast-fails its group and tears down that one session.
//
// method carries its own package -- "singbridge.PacketConnWrapper.ReadPacket",
// "shadowsocks_2022.Inbound.NewPacketConnection" -- because RecoverTo below is
// deferred from other packages too. A prefix hardcoded to this one would file
// their panics under singbridge and send whoever greps the label at 3am into
// the wrong package.
//
// The stack rides inside the error rather than being logged here: the error
// reaches a logger that holds the context -- Inbound.NewError, the outbound
// handler -- and therefore the connection id and user these methods lack.
func panicError(method string, r interface{}) error {
	return errors.New("panic in ", method, ": ", r, "\n", string(debug.Stack()))
}

// RecoverTo is the deferred form of panicError for entry points that have no
// closure of their own:
//
//	defer singbridge.RecoverTo(&err, "shadowsocks_2022.Inbound.NewPacketConnection")
//
// It must be the deferred function itself -- recover only works when called
// directly by one -- which is why the wrappers in this package inline the same
// two lines into their existing defers instead of calling this.
//
// What needs it: the methods sing calls a proxy with. Their bodies reach the
// inbound session, ToDestination and Dispatch -- routing, sniffing and DNS --
// so there is plenty to panic on, and the packet ones do not even share a
// stack with the goroutine that entered the proxy, since udpnat spawns one per
// NAT entry. Call sites carry a one-line note and point here rather than
// repeating this.
func RecoverTo(err *error, method string) {
	if r := recover(); r != nil {
		*err = panicError(method, r)
	}
}

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
	// waits for the tasks to return (sing v0.5.1: task.go:115 before
	// task.go:119). So Close runs while the download task is still inside
	// ReadPacket, on every cancelled session and every fast-failed upload.
	// Without this lock, Close releases the very buffer ReadPacket is copying
	// out of: Buffer.Release stores v = nil before Clear() resets start/end and
	// nils UDP last, so the racing Bytes() and *bb.UDP read a torn header -- a
	// nil base, a stale length, or an array already back in the pool and being
	// refilled by another session. One such interleaving took down a node
	// (SIGSEGV, 2026-08-22).
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
	defer func() {
		if r := recover(); r != nil {
			err = panicError("singbridge.PacketConnWrapper.ReadPacket", r)
		}
		if err != nil && w.T != nil {
			// uplinkonly
			w.T.SetTimeout(2 * time.Second)
		}
	}()
	w.T.Update()
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
	defer func() {
		if r := recover(); r != nil {
			err = panicError("singbridge.PacketConnWrapper.WritePacket", r)
		}
		if err != nil && w.T != nil {
			// downlinkonly
			w.T.SetTimeout(5 * time.Second)
		}
	}()
	w.T.Update()
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
