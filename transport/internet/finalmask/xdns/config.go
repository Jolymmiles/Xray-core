package xdns

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// HandleDial tells the finalmask that the client opens its own resolver
// sockets through the dialer, so no socket is dialed for it in advance. It
// also keeps xdns the innermost UDP mask, the only position where it works.
func (c *Config) HandleDial() {}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewClient(c, dialer)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn, addr net.Addr, lc *finalmask.ListenConfig) (net.PacketConn, error) {
	return NewServer(c, conn)
}
