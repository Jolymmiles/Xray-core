package finalmask

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// wholeDatagramConn reads a UDP socket below the masks of a path that hands
// each datagram on as it is. A mask hides the socket from the reader above,
// and what it takes off a packet hides the cut of one longer than the read:
// only the read of the socket itself shows it. ReadFrom drops such a datagram
// and reads the next, so that no mask decodes the start of a packet as a
// whole one.
type wholeDatagramConn struct {
	net.PacketConn
	socket *net.UDPConn
	drops  net.DropLog
}

// dropCutDatagrams returns conn reading as wholeDatagramConn does if it is a
// UDP socket, and conn itself otherwise.
func dropCutDatagrams(conn net.PacketConn) net.PacketConn {
	socket, ok := conn.(*net.UDPConn)
	if !ok {
		return conn
	}
	return &wholeDatagramConn{PacketConn: conn, socket: socket}
}

// ReadFrom reads a datagram that fits p. The flags of the read mark one that
// it cut short, and Windows fails such a read as too long.
func (c *wholeDatagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, _, flags, addr, err := c.socket.ReadMsgUDP(p, nil)
		if net.IsTruncated(flags) || net.IsMessageTooLong(err) {
			if c.drops.Due() {
				errors.LogDebug(context.Background(), "[mask] dropped a UDP datagram longer than the ", len(p), " bytes a read takes")
			}
			continue
		}
		if err != nil {
			return 0, nil, err
		}
		return n, addr, nil
	}
}
