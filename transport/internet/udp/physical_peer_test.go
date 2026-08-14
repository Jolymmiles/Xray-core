package udp

import (
	"context"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	corenet "github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport/internet"
)

func TestHubPublishesKernelPacketPeerSeparately(t *testing.T) {
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
	if _, err := client.Write([]byte("peer")); err != nil {
		t.Fatal(err)
	}

	select {
	case packet := <-hub.Receive():
		if packet == nil {
			t.Fatal("UDP hub closed before delivering packet")
		}
		defer buf.ReleaseMulti(buf.MultiBuffer{packet.Payload})
		if packet.PhysicalPeer != packet.Source {
			t.Fatalf("physical peer = %s, source = %s; want the kernel packet peer copied separately", packet.PhysicalPeer, packet.Source)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP packet")
	}
}

type syntheticPacketConn struct {
	gonet.PacketConn
	source gonet.Addr
}

func (c *syntheticPacketConn) ReadFrom(payload []byte) (int, gonet.Addr, error) {
	n, _, err := c.PacketConn.ReadFrom(payload)
	return n, c.source, err
}

func TestHubDoesNotTrustSyntheticMaskedSource(t *testing.T) {
	raw, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := &Hub{
		conn: &syntheticPacketConn{
			PacketConn: raw,
			source:     &gonet.UDPAddr{IP: gonet.ParseIP("198.18.0.1"), Port: 53},
		},
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
	if _, err := client.Write([]byte("masked")); err != nil {
		t.Fatal(err)
	}

	select {
	case packet := <-hub.Receive():
		if packet == nil {
			t.Fatal("UDP hub closed before delivering masked packet")
		}
		defer buf.ReleaseMulti(buf.MultiBuffer{packet.Payload})
		if packet.PhysicalPeer.IsValid() {
			t.Fatalf("synthetic masked source %s became trusted physical peer %s", packet.Source, packet.PhysicalPeer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for masked UDP packet")
	}
}
