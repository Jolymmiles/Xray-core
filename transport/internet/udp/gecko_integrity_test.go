package udp_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/udp"
	"google.golang.org/protobuf/proto"
)

// The UDP dialer (freedom, other outbounds' UDP) and the UDP hub (UDP
// inbounds) apply the stream's UDP masks whatever its network is, with no QUIC
// above them. A nominal QUIC network passes the stream config check, so these
// paths must refuse Gecko themselves unless an integrity mask sits outside it.
func TestRawUDPRefusesGeckoWithoutIntegrity(t *testing.T) {
	settings := func(masks ...proto.Message) *internet.MemoryStreamConfig {
		t.Helper()
		var typed []*serial.TypedMessage
		for _, mask := range masks {
			typed = append(typed, serial.ToTypedMessage(mask))
		}
		mss, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{ProtocolName: "hysteria", Udpmasks: typed})
		if err != nil {
			t.Fatalf("stream config: %v", err)
		}
		return mss
	}
	gecko := &salamander.GeckoConfig{Password: "gecko", MinPacketSize: 512, MaxPacketSize: 1200}
	ctx := context.Background()
	dest := net.UDPDestination(net.LocalHostIP, 9)

	unchecked := settings(gecko)
	if conn, err := internet.Dial(ctx, dest, unchecked); err == nil {
		conn.Close()
		t.Error("the UDP dialer used Gecko without integrity above it")
	}
	if hub, err := udp.ListenUDP(ctx, net.LocalHostIP, 0, unchecked); err == nil {
		hub.Close()
		t.Error("the UDP hub used Gecko without integrity above it")
	}

	checked := settings(&original.Config{}, gecko)
	conn, err := internet.Dial(ctx, dest, checked)
	if err != nil {
		t.Fatalf("the UDP dialer refused Gecko under a checksum mask: %v", err)
	}
	conn.Close()
	hub, err := udp.ListenUDP(ctx, net.LocalHostIP, 0, checked)
	if err != nil {
		t.Fatalf("the UDP hub refused Gecko under a checksum mask: %v", err)
	}
	hub.Close()
}
