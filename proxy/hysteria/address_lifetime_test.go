package hysteria

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type retainedDestinationDispatcher struct {
	routing.Dispatcher
	destination net.Destination
}

func (d *retainedDestinationDispatcher) DispatchLink(_ context.Context, destination net.Destination, _ *transport.Link) error {
	d.destination = destination
	return nil
}

type requestConnection struct{ net.Conn }

func (c requestConnection) SetReadDeadline(time.Time) error { return nil }

func TestServerTCPDestinationSurvivesRequestRelease(t *testing.T) {
	for _, address := range []string{"example.com:443", "192.0.2.1:443", "[2001:db8::1]:443"} {
		t.Run(address, func(t *testing.T) {
			wire := append([]byte{byte(len(address))}, address...)
			wire = append(wire, 0)
			conn := cnc.NewConnection(cnc.ConnectionOutput(bytes.NewReader(wire)), cnc.ConnectionInput(io.Discard))
			defer conn.Close()
			dispatcher := new(retainedDestinationDispatcher)
			ctx := session.ContextWithInbound(context.Background(), new(session.Inbound))
			if err := new(Server).Process(ctx, net.Network_TCP, requestConnection{conn}, dispatcher); err != nil {
				t.Fatal(err)
			}
			if got := dispatcher.destination.String(); got != "tcp:"+address {
				t.Fatalf("retained destination = %s, want tcp:%s", got, address)
			}
		})
	}
}

func TestServerUDPDestinationSurvivesReaderRelease(t *testing.T) {
	for _, packet := range []udpPacketDestination{
		{domain: "example.com", port: 53, isDomain: true},
		{ipv4: [4]byte{192, 0, 2, 1}, port: 53, isIPv4: true},
	} {
		reader := newPooledUDPReader(bytes.NewReader(nil))
		destination := reader.serverPacketDestination(packet)
		want := destination.String()
		reader.serverPacketDestination(udpPacketDestination{domain: "next.example", port: 53, isDomain: true})
		reader.serverPacketDestination(udpPacketDestination{ipv4: [4]byte{192, 0, 2, 2}, port: 53, isIPv4: true})
		releasePooledUDPReader(reader)
		if got := destination.String(); got != want {
			t.Fatalf("retained destination = %s, want %s", got, want)
		}
	}
}
