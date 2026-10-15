package udp

import (
	"bytes"
	"context"
	gonet "net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	corenet "github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport/internet"
)

// receiveDatagrams returns the payloads of the next n datagrams that hub
// passes on, and fails if it stops serving first.
func receiveDatagrams(t *testing.T, hub *Hub, n int) [][]byte {
	t.Helper()
	var got [][]byte
	for len(got) < n {
		select {
		case packet := <-hub.Receive():
			if packet == nil {
				t.Fatalf("the hub stopped serving after %d datagrams", len(got))
			}
			got = append(got, bytes.Clone(packet.Payload.Bytes()))
			packet.Payload.Release()
		case <-time.After(5 * time.Second):
			t.Fatalf("the hub passed on %d datagrams, want %d", len(got), n)
		}
	}
	return got
}

// A datagram longer than the hub's buffer of buf.Size bytes came out of the
// read cut to that buffer, and the inbound passed its start on as a datagram
// of its own. The hub drops it where the read reports the cut: Linux and
// OpenBSD mark the read with MSG_TRUNC, and Windows fails it. It passes on a
// datagram that fills the buffer exactly, and the one after.
func TestHubDropsDatagramsLongerThanItsBuffer(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "android", "openbsd", "windows":
	default:
		t.Skipf("the hub of %s reads without the flags that mark a cut datagram", runtime.GOOS)
	}
	hub, err := ListenUDP(context.Background(), corenet.LocalHostIP, 0, &internet.MemoryStreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	client, err := gonet.DialUDP("udp", nil, hub.Addr().(*gonet.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	sent := [][]byte{bytes.Repeat([]byte{1}, buf.Size+1), bytes.Repeat([]byte{2}, buf.Size), []byte("ping")}
	for _, payload := range sent {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	for i, got := range receiveDatagrams(t, hub, 2) {
		if want := sent[i+1]; !bytes.Equal(got, want) {
			t.Fatalf("datagram %d: the hub passed on %d bytes of %#x, want %d of %#x", i, len(got), got[0], len(want), want[0])
		}
	}
}

// tooLongPacketConn fails its first read as Windows fails one that cut a
// datagram short, with a "message too long" error, and then reads the socket
// it wraps.
type tooLongPacketConn struct {
	gonet.PacketConn
	failed bool
}

func (c *tooLongPacketConn) ReadFrom(p []byte) (int, gonet.Addr, error) {
	if !c.failed {
		c.failed = true
		return len(p), nil, &gonet.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("wsarecvfrom", syscall.EMSGSIZE)}
	}
	return c.PacketConn.ReadFrom(p)
}

// Windows fails a read that cut a datagram short with WSAEMSGSIZE, and the
// hub stopped serving on any read error: one long datagram from anyone ended
// the UDP side of the inbound until a restart. The hub drops that datagram and
// serves the next.
func TestHubServesOnAfterAReadOfATooLongDatagram(t *testing.T) {
	raw, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := &Hub{
		conn:     &tooLongPacketConn{PacketConn: raw},
		cache:    make(chan *protocoludp.Packet, 1),
		capacity: 1,
	}
	t.Cleanup(func() { _ = hub.Close() })
	go hub.start()

	client, err := gonet.DialUDP("udp", nil, raw.LocalAddr().(*gonet.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got := receiveDatagrams(t, hub, 1)[0]; string(got) != "ping" {
		t.Fatalf("the hub passed on %q, want %q", got, "ping")
	}
}

// Any other read error still ends the hub, as a closed socket does: the hub
// stops serving and closes its channel instead of reading on.
func TestHubStopsServingOnOtherReadErrors(t *testing.T) {
	hub, err := ListenUDP(context.Background(), corenet.LocalHostIP, 0, &internet.MemoryStreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case packet, open := <-hub.Receive():
		if open {
			packet.Payload.Release()
			t.Fatal("the hub passed on a datagram from a closed socket")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hub kept reading its closed socket")
	}
}
