package freedom

import (
	"bytes"
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

// A UDP mask hides the socket from freedom's reader, which then read without
// the flags that mark a cut datagram. Behind Salamander a reply of 9000 bytes
// came out as 8184: the socket cut the packet to the 8192 bytes of the read
// and the mask took its 8 bytes of salt off, so no spare byte in freedom's
// buffer could show the cut, and the Trojan writer, which now frames a payload
// of that size, sent it to the client. The masks of the UDP dialer now read a
// socket that drops such a packet itself.
func TestPacketReaderDropsRepliesCutBelowAMask(t *testing.T) {
	const password = "mask-password"
	server, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	socket, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	dialUDP := func(context.Context, net.Destination) (stdnet.PacketConn, stdnet.Addr, error) {
		return socket, server.LocalAddr(), nil
	}
	masks := finalmask.NewFinalMask(nil, []finalmask.UDPMask{&salamander.Config{Password: password}}, nil, nil, dialUDP, nil)
	destination := net.DestinationFromAddr(server.LocalAddr())
	conn, err := internet.Dial(context.Background(), destination, &internet.MemoryStreamConfig{FinalMask: masks})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// The mask's own writer sends no more than 4096 bytes, so the server
	// obfuscates its replies itself.
	obfuscator, err := salamander.NewSalamanderObfuscator([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	const saltLen = 8
	sent := [][]byte{bytes.Repeat([]byte{1}, 9000), bytes.Repeat([]byte{2}, buf.Size-saltLen), []byte("pong")}
	for _, reply := range sent {
		packet := make([]byte, len(reply)+saltLen)
		if n := obfuscator.Obfuscate(reply, packet); n != len(packet) {
			t.Fatalf("obfuscated %d bytes of a packet of %d", n, len(packet))
		}
		if n, err := server.WriteTo(packet, socket.LocalAddr()); err != nil || n != len(packet) {
			t.Fatalf("wrote %d bytes of a packet of %d: %v", n, len(packet), err)
		}
	}

	reader := NewPacketReader(context.Background(), conn, &Handler{}, nil, net.Destination{}, destination)
	for _, want := range sent[1:] {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("waiting for the reply of %d bytes: %v", len(want), err)
		}
		got := bytes.Clone(mb[0].Bytes())
		buf.ReleaseMulti(mb)
		if !bytes.Equal(got, want) {
			t.Fatalf("passed on %d bytes of %#x, want the reply of %d bytes of %#x", len(got), got[0], len(want), want[0])
		}
	}
}
