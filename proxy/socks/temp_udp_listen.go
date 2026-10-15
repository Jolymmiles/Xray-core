package socks

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
)

func NewTempUDPConn(udpConn net.PacketConn, tcpConn net.Conn, expectedRemote *net.UDPAddr) *TempUDPConn {
	t := &TempUDPConn{
		PacketConn:        udpConn,
		AssociatedTCPConn: tcpConn,
	}
	t.ExpectedRemote.Store(expectedRemote)
	return t
}

// TempUDPConn wait for the first packet to determine the remote address
// SetTimeout MUST be called before any read/write operation
type TempUDPConn struct {
	net.PacketConn
	AssociatedTCPConn net.Conn
	ExpectedRemote    atomic.Pointer[net.UDPAddr]
	Timer             *signal.ActivityTimer
}

func (c *TempUDPConn) Read(b []byte) (n int, err error) {
	var remote net.Addr
	for {
		var cut bool
		n, remote, cut, err = c.readFrom(b)
		if cut {
			// a read takes up to len(b) bytes: drop a longer datagram rather
			// than pass its start on as a datagram of its own
			xnet.LogDroppedDatagram(context.Background(), -1, "longer than the buffer a read takes")
			continue
		}
		if err != nil {
			return
		}
		remote := remote.(*net.UDPAddr)
		expected := c.ExpectedRemote.Load()
		if remote.IP.Equal(expected.IP) {
			if remote.Port == expected.Port {
				c.Timer.Update()
				return
			}
			if expected.Port == 0 {
				c.ExpectedRemote.Store(remote)
				c.Timer.Update()
				return
			}
		}
	}
}

// readFrom reads a datagram into b, and reports whether the read cut it short:
// Linux, macOS and the BSDs mark such a read, and Windows fails it.
func (c *TempUDPConn) readFrom(b []byte) (int, net.Addr, bool, error) {
	socket, ok := c.PacketConn.(*net.UDPConn)
	if !ok {
		n, remote, err := c.PacketConn.ReadFrom(b)
		return n, remote, false, err
	}
	n, _, flags, remote, err := socket.ReadMsgUDP(b, nil)
	if xnet.IsMessageTooLong(err) {
		return 0, nil, true, nil
	}
	return n, remote, xnet.IsTruncated(flags), err
}

func (c *TempUDPConn) Write(b []byte) (n int, err error) {
	c.Timer.Update()
	return c.PacketConn.WriteTo(b, c.ExpectedRemote.Load())
}

func (c *TempUDPConn) RemoteAddr() net.Addr {
	return c.ExpectedRemote.Load()
}

func (c *TempUDPConn) SetTimeout(d time.Duration) {
	c.Timer = signal.CancelAfterInactivity(context.Background(), func() {
		c.Close()
	}, d)
}

func (c *TempUDPConn) Close() error {
	c.Timer.SetTimeout(0)
	c.AssociatedTCPConn.Close()
	return c.PacketConn.Close()
}
