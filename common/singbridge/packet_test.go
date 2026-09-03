package singbridge

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
)

// multiDatagramReader returns several datagrams per read, which is what leaves
// anything in PacketConnWrapper.cached. A reader handing back one buffer at a
// time would drain cached on every call and exercise nothing.
type multiDatagramReader struct {
	perRead int
	payload []byte
}

func (r *multiDatagramReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := make(buf.MultiBuffer, 0, r.perRead)
	for i := 0; i < r.perRead; i++ {
		b := buf.New()
		b.Write(r.payload)
		mb = append(mb, b)
	}
	return mb, nil
}

// TestPacketConnWrapperCloseRacesReadPacket is the regression test for the
// crash on pl-warsaw, 2026-08-22.
//
// sing's task.Group runs its cleanup -- common.Close on both ends of the copy,
// so this type's Close -- as soon as the group context is done, and only waits
// for the tasks afterwards (sing v0.5.1: task.go:115 before task.go:119). Close
// therefore lands on this wrapper while the download task is still inside
// ReadPacket, which happens on every cancelled session and every fast-failed
// upload.
//
// Before the fix the two shared cached with no synchronisation, so Close
// released the buffer ReadPacket was copying out of: Buffer.Release stores
// v = nil before Clear() resets start/end, so the racing Bytes() read a torn
// header. That was the SIGSEGV in the report, and it killed the process rather
// than the session because these goroutines belong to sing and no recover()
// covered them.
//
// Run under -race. The crash needs an unlucky interleaving; the data race
// underneath it does not, and that is what this asserts on.
func TestPacketConnWrapperCloseRacesReadPacket(t *testing.T) {
	const (
		rounds = 50
		reads  = 64
	)
	payload := bytes.Repeat([]byte{'x'}, 1122)

	for round := 0; round < rounds; round++ {
		timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
		w := &PacketConnWrapper{
			Reader: &multiDatagramReader{perRead: 16, payload: payload},
			Dest:   net.UDPDestination(net.LocalHostIP, 443),
			T:      timer,
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < reads; i++ {
				b := B.NewSize(2048)
				if _, err := w.ReadPacket(b); err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}()
		go func() {
			defer wg.Done()
			if err := w.Close(); err != nil {
				t.Error("Close: ", err)
			}
		}()
		wg.Wait()

		// Idempotence: sing closes both ends of a group and a caller may close
		// again. A second pass over the same slice would put the same arrays
		// into the pool twice.
		if err := w.Close(); err != nil {
			t.Fatal("second Close: ", err)
		}
		timer.SetTimeout(0)
	}
}

// TestPacketConnWrapperReadPacketAfterClose covers the other side of the same
// window: ReadPacket blocked in ReadMultiBuffer when Close runs, returning with
// a tail to stash into a slice Close has already walked. Stashing it there
// would strand every buffer in it -- the pool never sees them again.
func TestPacketConnWrapperReadPacketAfterClose(t *testing.T) {
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	defer timer.SetTimeout(0)

	w := &PacketConnWrapper{
		Reader: &multiDatagramReader{perRead: 8, payload: []byte("payload")},
		Dest:   net.UDPDestination(net.LocalHostIP, 443),
		T:      timer,
	}
	if err := w.Close(); err != nil {
		t.Fatal("Close: ", err)
	}

	b := B.NewSize(2048)
	defer b.Release()
	if _, err := w.ReadPacket(b); err != nil {
		t.Fatal("ReadPacket after Close: ", err)
	}

	w.cachedMu.Lock()
	cached := w.cached
	w.cachedMu.Unlock()
	if cached != nil {
		t.Fatalf("ReadPacket stashed %d buffers after Close; they would never be released", len(cached))
	}
}

// panickingReader stands in for whatever nil-derefs next. The point of the
// guard is that it holds for a panic this repository has never seen, since the
// one it was written for is fixed above.
type panickingReader struct{}

func (panickingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	var b *buf.Buffer
	_ = b.Bytes() // nil *Buffer dereference, the shape of the production crash
	return nil, nil
}

type panickingWriter struct{}

func (panickingWriter) WriteMultiBuffer(buf.MultiBuffer) error {
	panic("write side exploded")
}

// TestPacketConnWrapperRecoversPanic asserts the containment the report asked
// for: sing runs these methods on goroutines from task.Group and udpnat, which
// no caller's recover reaches, so a panic that escapes here ends the process
// rather than the session.
func TestPacketConnWrapperRecoversPanic(t *testing.T) {
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	defer timer.SetTimeout(0)

	w := &PacketConnWrapper{
		Reader: panickingReader{},
		Writer: panickingWriter{},
		Dest:   net.UDPDestination(net.LocalHostIP, 443),
		T:      timer,
	}

	b := B.NewSize(2048)
	defer b.Release()
	_, err := w.ReadPacket(b)
	if err == nil {
		t.Fatal("ReadPacket returned no error for a panicking reader")
	}
	if !strings.Contains(err.Error(), "panic in singbridge.PacketConnWrapper.ReadPacket") {
		t.Fatalf("ReadPacket error does not name the panic: %v", err)
	}
	// The stack is what an operator needs to find the next one; it has to ride
	// inside the error, because these methods hold no context to log it with.
	if !strings.Contains(err.Error(), "singbridge.(*PacketConnWrapper).ReadPacket") {
		t.Fatalf("ReadPacket error carries no stack: %v", err)
	}

	wb := B.NewSize(2048)
	defer wb.Release()
	wb.Write([]byte("payload"))
	err = w.WritePacket(wb, ToSocksaddr(net.UDPDestination(net.LocalHostIP, 443)))
	if err == nil {
		t.Fatal("WritePacket returned no error for a panicking writer")
	}
	if !strings.Contains(err.Error(), "panic in singbridge.PacketConnWrapper.WritePacket") {
		t.Fatalf("WritePacket error does not name the panic: %v", err)
	}
}

// TestRecoverTo pins the two things about RecoverTo that are easy to break: it
// must be the deferred function itself -- wrapped in another closure, recover()
// returns nil and the panic goes straight through -- and the package in the
// message must be the caller's, not this one's.
func TestRecoverTo(t *testing.T) {
	err := func() (err error) {
		defer RecoverTo(&err, "caller.Method")
		panic("boom")
	}()
	if err == nil || !strings.Contains(err.Error(), "panic in caller.Method: boom") {
		t.Fatalf("RecoverTo did not convert the panic: %v", err)
	}
}
