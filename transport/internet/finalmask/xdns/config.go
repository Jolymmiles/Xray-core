package xdns

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/errors"
)

func (c *Config) UDP() {
}

// Level policy: the received implementation shipped the outermost-level
// guards commented out (dead code referencing FakePacketConn/UdpHop), so
// nested wrapping already worked in practice. Keep accepting it - operators
// do combine xdns with inner transports - but warn loudly at wrap time:
// every extra layer shrinks the usable DNS name budget below the measured
// client payload ceiling, and a mixed stack can silently degrade throughput.
func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	if level != 0 || levelCount > 1 {
		errors.LogWarning(context.Background(), "xdns wrapped at non-outermost level ", level, "/", levelCount, "; inner layers shrink the DNS name budget below the measured payload ceiling")
	}
	return NewConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	if level != 0 || levelCount > 1 {
		errors.LogWarning(context.Background(), "xdns wrapped at non-outermost level ", level, "/", levelCount, "; responses are sized for the outer socket and may truncate through extra layers")
	}
	return NewConnServer(c, raw)
}
