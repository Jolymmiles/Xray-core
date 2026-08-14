package udp

import (
	"testing"

	X "github.com/xtls/xray-core/common/net"
)

func TestPacketPhysicalPeerIsIndependentFromEffectiveAndOriginalDestinations(t *testing.T) {
	peer := X.UDPDestination(X.ParseAddress("192.0.2.19"), 41000)
	packet := Packet{
		Source:       X.UDPDestination(X.ParseAddress("198.51.100.7"), 53),
		Target:       X.UDPDestination(X.ParseAddress("203.0.113.9"), 443),
		PhysicalPeer: peer,
	}
	if packet.PhysicalPeer != peer || packet.PhysicalPeer == packet.Source || packet.PhysicalPeer == packet.Target {
		t.Fatalf("packet provenance coupled to rewritten metadata: %+v", packet)
	}
}
