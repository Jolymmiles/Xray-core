package xudp

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// A server may send a packet above buf.Size, which Xray's writer does not, up
// to the 65535 bytes the length allows. The reader failed on it, which ended
// the mux connection with every session on it; it must read the packet whole
// and then the packets after it.
func TestPacketReaderKeepsLargePacketsWhole(t *testing.T) {
	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
	frame := func(payload []byte) []byte {
		t.Helper()
		var frames buf.MultiBufferContainer
		b := buf.New()
		common.Must2(b.Write([]byte("a")))
		b.UDP = &destination
		common.Must(NewPacketWriter(&frames, net.TCPDestination(net.LocalHostIP, 1), [8]byte{}).WriteMultiBuffer(buf.MultiBuffer{b}))
		header := make([]byte, frames.Len())
		frames.Copy(header)
		buf.ReleaseMulti(frames.MultiBuffer)
		// The frame of "a" ends with its 2-byte length and "a": put payload
		// in their place, which the writer would have dropped.
		header = header[:len(header)-3]
		out := append(bytes.Clone(header), byte(len(payload)>>8), byte(len(payload)))
		return append(out, payload...)
	}
	large := bytes.Repeat([]byte{7}, 9000)
	var stream bytes.Buffer
	stream.Write(frame(large))
	stream.Write(frame([]byte("pong")))

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
