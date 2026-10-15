package xudp

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// peerFrame returns the frame of a packet to destination, which a peer sends
// in a session it opened with an earlier frame.
func peerFrame(t *testing.T, destination net.Destination, payload []byte) []byte {
	t.Helper()
	var frames buf.MultiBufferContainer
	b := buf.New()
	common.Must2(b.Write([]byte("a")))
	b.UDP = &destination
	common.Must(NewPacketWriter(&frames, net.TCPDestination(net.LocalHostIP, 1), [8]byte{}).WriteMultiBuffer(buf.MultiBuffer{b}))
	header := make([]byte, frames.Len())
	frames.Copy(header)
	buf.ReleaseMulti(frames.MultiBuffer)
	// The frame of "a" ends with its 2-byte length and "a": put payload in
	// their place, which the writer would have dropped.
	header = header[:len(header)-3]
	out := append(bytes.Clone(header), byte(len(payload)>>8), byte(len(payload)))
	return append(out, payload...)
}

// A server may send a packet above buf.Size, which Xray's writer does not, up
// to the 65535 bytes the length allows. The reader failed on it, which ended
// the mux connection with every session on it; it must read the packet whole
// and then the packets after it.
func TestPacketReaderKeepsLargePacketsWhole(t *testing.T) {
	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
	large := bytes.Repeat([]byte{7}, 9000)
	var stream bytes.Buffer
	stream.Write(peerFrame(t, destination, large))
	stream.Write(peerFrame(t, destination, []byte("pong")))

	reader := NewPacketReader(&stream)
	for _, want := range [][]byte{large, []byte("pong")} {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("reading the packet of %d bytes: %v", len(want), err)
		}
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), want) {
			t.Fatalf("read %d buffers of %d bytes, want the packet of %d bytes", len(mb), mb.Len(), len(want))
		}
		if mb[0].UDP == nil || *mb[0].UDP != destination {
			t.Fatalf("the packet is addressed to %v, want %v", mb[0].UDP, destination)
		}
		buf.ReleaseMulti(mb)
	}
}

// arrivingStream hands out its bytes one at a time, as a peer's bytes arrive,
// and records the largest buffer a reader offered for them.
type arrivingStream struct {
	bytes   *bytes.Reader
	largest int
}

func (s *arrivingStream) Read(p []byte) (int, error) {
	s.largest = max(s.largest, cap(p))
	return s.bytes.Read(p[:min(len(p), 1)])
}

// A server sends the length of a packet before its bytes and may stall in
// between. The reader took a buffer of the packet's size, up to 128 KiB, as
// soon as the length arrived. It must read the bytes into buffers of buf.Size
// as they arrive, so that a stalled server holds no more memory than it sent,
// and still return the packet whole.
func TestPacketReaderTakesMemoryAsThePacketArrives(t *testing.T) {
	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
	for _, size := range []int{buf.Size, buf.Size + 1, 9000, 65535} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		stream := &arrivingStream{bytes: bytes.NewReader(peerFrame(t, destination, payload))}
		mb, err := NewPacketReader(stream).ReadMultiBuffer()
		if err != nil {
			t.Fatalf("reading a packet of %d bytes: %v", size, err)
		}
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || mb[0].UDP == nil || *mb[0].UDP != destination {
			t.Fatalf("read %d buffers of %d bytes, want the packet of %d bytes to %v whole", len(mb), mb.Len(), size, destination)
		}
		buf.ReleaseMulti(mb)
		if stream.largest > buf.Size {
			t.Fatalf("a packet of %d bytes was read into a buffer of %d bytes before it arrived, want at most %d", size, stream.largest, buf.Size)
		}
	}
}
