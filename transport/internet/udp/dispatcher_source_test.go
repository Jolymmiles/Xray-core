package udp_test

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport"
	. "github.com/xtls/xray-core/transport/internet/udp"
)

// scriptedReader returns one buffer per call, made when it is read, then EOF.
type scriptedReader struct {
	mu    sync.Mutex
	steps []func() *buf.Buffer
}

func (r *scriptedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.steps) == 0 {
		return nil, io.EOF
	}
	step := r.steps[0]
	r.steps = r.steps[1:]
	return buf.MultiBuffer{step()}, nil
}

type discardWriter struct{}

func (discardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

// A response packet's address may live in its buffer's pooled metadata, as
// the Hysteria UDP reader stores it. Consumers release the packet after the
// callback, so the dispatcher must not keep pointing into that buffer: the
// next packet without an address takes the previous source, and a source a
// callback kept must not change when the buffer is reused.
func TestDispatcherSourceOutlivesPacketBuffer(t *testing.T) {
	ipv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	reader := &scriptedReader{steps: []func() *buf.Buffer{
		func() *buf.Buffer {
			b := buf.New()
			b.WriteString("first")
			b.SetManagedUDPIPv6(ipv6, 443)
			return b
		},
		func() *buf.Buffer {
			b := buf.New()
			b.WriteString("second") // no address: the previous source applies
			return b
		},
		func() *buf.Buffer {
			b := buf.New()
			b.WriteString("third")
			b.SetManagedUDPIPv4([4]byte{192, 0, 2, 7}, 53) // reuses a released slab
			return b
		},
	}}
	dispatcher := &TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return &transport.Link{Reader: reader, Writer: discardWriter{}}, nil
	}}

	var mu sync.Mutex
	var kept []net.Destination
	var seen []string
	received := make(chan struct{}, 3)
	udpDispatcher := NewDispatcher(dispatcher, func(_ context.Context, packet *udp.Packet) {
		mu.Lock()
		kept = append(kept, packet.Source)
		seen = append(seen, packet.Source.NetAddr())
		mu.Unlock()
		packet.Payload.Release()
		received <- struct{}{}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := buf.New()
	request.WriteString("request")
	udpDispatcher.Dispatch(ctx, net.UDPDestination(net.IPv6Address(ipv6), 443), request)

	for range 3 {
		select {
		case <-received:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for dispatched responses")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"[2001:db8::1]:443", "[2001:db8::1]:443", "192.0.2.7:53"}
	for index := range want {
		if seen[index] != want[index] {
			t.Errorf("packet %d source at callback = %s, want %s", index, seen[index], want[index])
		}
		if got := kept[index].NetAddr(); got != want[index] {
			t.Errorf("packet %d source kept after release = %s, want %s", index, got, want[index])
		}
	}
}
