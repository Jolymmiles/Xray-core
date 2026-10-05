package masque

import (
	"errors"
	stdnet "net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/internet/masque"
	"golang.zx2c4.com/wireguard/tun"
)

// stubDevice is a tun.Device whose reads serve a fixed number of packets and
// whose writes block until the test releases them.
type stubDevice struct {
	packets   int
	served    chan struct{}
	release   chan struct{}
	closeOnce sync.Once
	closed    chan struct{}
}

func newStubDevice(packets int) *stubDevice {
	return &stubDevice{packets: packets, served: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
}

func (d *stubDevice) Read(bufs [][]byte, sizes []int, _ int) (int, error) {
	if d.packets == 0 {
		close(d.served)
		<-d.closed
		return 0, os.ErrClosed
	}
	d.packets--
	sizes[0] = copy(bufs[0], []byte{0x45, 0, 0, 20})
	return 1, nil
}

func (d *stubDevice) Write(bufs [][]byte, _ int) (int, error) {
	select {
	case <-d.release:
	case <-d.closed:
	}
	return len(bufs), nil
}

func (d *stubDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (d *stubDevice) File() *os.File           { return nil }
func (d *stubDevice) MTU() (int, error)        { return masque.MinPacketSize, nil }
func (d *stubDevice) Name() (string, error)    { return "stub", nil }
func (d *stubDevice) Events() <-chan tun.Event { return nil }
func (d *stubDevice) BatchSize() int           { return 1 }

// tooBigConn rejects every packet as too big for the tunnel and receives
// nothing until it is closed.
type tooBigConn struct {
	stdnet.Conn
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *tooBigConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, os.ErrClosed
}

func (c *tooBigConn) Write([]byte) (int, error) {
	return 0, &masque.PacketTooBigError{ICMP: []byte{0x45, 0, 0, 28}}
}

func (c *tooBigConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// Each packet too big for the tunnel produces an ICMP reply to the local
// stack. While that stack does not accept writes, the replies must not pile
// up one goroutine per packet.
func TestTunnelBoundsPacketTooBigReplies(t *testing.T) {
	const packets = 256
	dev := newStubDevice(packets)
	before := runtime.NumGoroutine()
	tunnel := startTunnel(&tooBigConn{closed: make(chan struct{})}, dev, nil)
	t.Cleanup(func() {
		tunnel.close()
		close(dev.release)
	})
	select {
	case <-dev.served:
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not read every packet")
	}
	if grown := runtime.NumGoroutine() - before; grown > 16 {
		t.Fatalf("%d packets too big for the tunnel left %d goroutines behind", packets, grown)
	}
}

type discardConn struct {
	stdnet.Conn
}

func (discardConn) Write(p []byte) (int, error) { return 0, errors.New("tunnel closed") }

// Closing a tunnel must release the packets still queued for it.
func TestServerTunnelReleasesQueuedPacketsOnClose(t *testing.T) {
	server := &Server{dev: newStubDevice(0)}
	tunnel := newServerTunnel(discardConn{}, nil)
	for range tunnelQueueSize {
		packet := buf.New()
		packet.Extend(20)
		if !tunnel.send(packet) {
			t.Fatal("queue refused a packet before close")
		}
	}
	tunnel.close()
	server.writeToTunnel(tunnel)
	if queued := len(tunnel.queue); queued != 0 {
		t.Fatalf("%d packets stayed queued after the tunnel closed", queued)
	}
	late := buf.New()
	defer late.Release()
	if tunnel.send(late) {
		t.Fatal("closed tunnel accepted a packet")
	}
}
