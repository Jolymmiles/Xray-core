package splithttp

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

type splitConn struct {
	writer        io.WriteCloser
	reader        io.ReadCloser
	remoteAddr    net.Addr
	localAddr     net.Addr
	onClose       func()
	muxKeepAlive  *RangeConfig
	muxKeepAliveB *RangeConfig
	lastWrite     atomic.Int64
}

// MuxKeepAlive reports how long, in seconds, this downlink may carry nothing
// before a Mux.Cool server should poke it. It is only set where the downlink is
// a long-lived response of its own, as in packet-up and stream-up, which is what
// CDN idle timers cut.
func (c *splitConn) MuxKeepAlive() (int32, int32) {
	if c.muxKeepAlive == nil {
		return 0, 0
	}
	return c.muxKeepAlive.From, c.muxKeepAlive.To
}

// MuxKeepAliveBytes reports how much padding to hide in each such poke, so that
// they do not all leave at one telling size.
func (c *splitConn) MuxKeepAliveBytes() (int32, int32) {
	if c.muxKeepAliveB == nil {
		return 0, 0
	}
	return c.muxKeepAliveB.From, c.muxKeepAliveB.To
}

// DownlinkIdle reports how long this downlink has carried nothing.
func (c *splitConn) DownlinkIdle() time.Duration {
	return time.Since(time.Unix(0, c.lastWrite.Load()))
}

func (c *splitConn) Write(b []byte) (int, error) {
	n, err := c.writer.Write(b)
	c.lastWrite.Store(time.Now().UnixNano())
	return n, err
}

func (c *splitConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}

	err := c.writer.Close()
	err2 := c.reader.Close()
	if err != nil {
		return err
	}

	if err2 != nil {
		return err
	}

	return nil
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}
