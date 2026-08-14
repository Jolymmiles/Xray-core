package udp

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// Packet is a UDP packet together with effective, original-destination, and
// optional server-observed peer metadata. PhysicalPeer is independent of Source
// and remains invalid when an adapter exposes only a synthetic address.
type Packet struct {
	Payload      *buf.Buffer
	Source       net.Destination
	Target       net.Destination
	PhysicalPeer net.Destination
}
