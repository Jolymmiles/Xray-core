package singbridge

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
)

type packetReadFunc func() (buf.MultiBuffer, error)

func (f packetReadFunc) ReadMultiBuffer() (buf.MultiBuffer, error) { return f() }

func TestPacketReadClosedDuringReadReleasesBuffers(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	first, tail := buf.New(), buf.New()
	first.Write([]byte("first"))
	tail.Write([]byte("tail"))
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	defer timer.SetTimeout(0)
	w := &PacketConnWrapper{Reader: packetReadFunc(func() (buf.MultiBuffer, error) {
		close(started)
		<-resume
		return buf.MultiBuffer{first, tail}, nil
	}), Dest: net.UDPDestination(net.LocalHostIP, 53), T: timer}
	output := B.NewSize(64)
	defer output.Release()
	done := make(chan error, 1)
	go func() { _, err := w.ReadPacket(output); done <- err }()
	<-started
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	close(resume)
	if err := <-done; !errors.Is(err, stdnet.ErrClosed) {
		t.Errorf("read after close = %v, want stdnet.ErrClosed", err)
	}
	if first.Len() != 0 || tail.Len() != 0 {
		t.Errorf("closed read retained buffers: first=%d tail=%d", first.Len(), tail.Len())
	}
	// Cleanup also lets this regression fail without retaining pooled storage.
	first.Release()
	tail.Release()
}

func TestPacketReadPreservesTerminalError(t *testing.T) {
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	defer timer.SetTimeout(0)
	w := &PacketConnWrapper{Reader: packetReadFunc(func() (buf.MultiBuffer, error) { return nil, io.EOF }), T: timer}
	output := B.NewSize(64)
	defer output.Release()
	if _, err := w.ReadPacket(output); !errors.Is(err, io.EOF) {
		t.Fatalf("read error = %v, want EOF", err)
	}
}

func TestPacketReadCloseConcurrent(t *testing.T) {
	for range 100 {
		timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
		first, tail := buf.New(), buf.New()
		first.Write([]byte("first"))
		tail.Write([]byte("tail"))
		w := &PacketConnWrapper{Reader: packetReadFunc(func() (buf.MultiBuffer, error) { return buf.MultiBuffer{first, tail}, nil }), Dest: net.UDPDestination(net.LocalHostIP, 53), T: timer}
		output := B.NewSize(64)
		if _, err := w.ReadPacket(output); err != nil {
			t.Fatal(err)
		}
		output.Reset()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := w.ReadPacket(output)
			if err != nil && !errors.Is(err, stdnet.ErrClosed) {
				t.Errorf("read: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := w.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}()
		close(start)
		wg.Wait()
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		output.Release()
		timer.SetTimeout(0)
	}
}

func TestPacketReadDrainsPayloadBeforeTerminalError(t *testing.T) {
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	defer timer.SetTimeout(0)
	first, second := buf.New(), buf.New()
	first.Write([]byte("first"))
	second.Write([]byte("second"))
	second.SetManagedUDPIPv4([4]byte{192, 0, 2, 8}, 123)
	reads := 0
	w := &PacketConnWrapper{Reader: packetReadFunc(func() (buf.MultiBuffer, error) {
		reads++
		if reads > 1 {
			return nil, errors.New("reader called after terminal error")
		}
		return buf.MultiBuffer{first, second}, io.EOF
	}), Dest: net.UDPDestination(net.LocalHostIP, 53), T: timer}
	defer w.Close()
	output := B.NewSize(64)
	defer output.Release()
	for _, want := range []struct{ payload, address string }{{"first", "127.0.0.1:53"}, {"second", "192.0.2.8:123"}} {
		output.Reset()
		address, err := w.ReadPacket(output)
		if err != nil || string(output.Bytes()) != want.payload || address.String() != want.address {
			t.Fatalf("read = %q %v %v; want %q %s", output.Bytes(), address, err, want.payload, want.address)
		}
	}
	if _, err := w.ReadPacket(output); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal error = %v, want EOF", err)
	}
}

func TestPacketReadRejectsTruncatedDatagram(t *testing.T) {
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	defer timer.SetTimeout(0)
	packet := buf.New()
	packet.Write([]byte("too large"))
	w := &PacketConnWrapper{Reader: packetReadFunc(func() (buf.MultiBuffer, error) { return buf.MultiBuffer{packet}, io.EOF }), Dest: net.UDPDestination(net.LocalHostIP, 53), T: timer}
	defer w.Close()
	output := B.NewSize(2)
	defer output.Release()
	if _, err := w.ReadPacket(output); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("read error = %v, want short buffer", err)
	}
	if packet.Len() != 0 {
		t.Fatal("truncated datagram buffer not released")
	}
}
