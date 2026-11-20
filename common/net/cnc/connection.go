package cnc

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

type ConnectionOption func(*Connection)

func ConnectionLocalAddr(a net.Addr) ConnectionOption {
	return func(c *Connection) {
		c.local = a
	}
}

func ConnectionRemoteAddr(a net.Addr) ConnectionOption {
	return func(c *Connection) {
		c.remote = a
	}
}

func ConnectionInput(writer io.Writer) ConnectionOption {
	return func(c *Connection) {
		c.writer = buf.NewWriter(writer)
		c.writeCloser, _ = writer.(io.Closer)
	}
}

func ConnectionInputMulti(writer buf.Writer) ConnectionOption {
	return func(c *Connection) {
		c.writer = writer
		c.writeCloser, _ = writer.(io.Closer)
	}
}

func ConnectionOutput(reader io.Reader) ConnectionOption {
	return func(c *Connection) {
		c.reader = &buf.BufferedReader{Reader: buf.NewReader(reader)}
	}
}

func ConnectionOutputMulti(reader buf.Reader) ConnectionOption {
	return func(c *Connection) {
		c.reader = &buf.BufferedReader{Reader: reader}
	}
}

// ConnectionOutputMultiUDP makes a connection for a UDP destination: reader
// returns a datagram per buffer and Read returns one per call, dropping one
// longer than the buffer it reads into, and Write writes one per call.
func ConnectionOutputMultiUDP(reader buf.Reader) ConnectionOption {
	return func(c *Connection) {
		c.datagrams = true
		c.reader = &buf.BufferedReader{
			Reader:   reader,
			Splitter: c.splitFirstDatagram,
		}
	}
}

func ConnectionOnClose(n io.Closer) ConnectionOption {
	return func(c *Connection) {
		c.onClose = n
	}
}

func NewConnection(opts ...ConnectionOption) net.Conn {
	c := &Connection{
		done: done.New(),
		local: &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		},
		remote: &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

type Connection struct {
	reader         *buf.BufferedReader
	writer         buf.Writer
	writeCloser    io.Closer
	writeCloseOnce sync.Once
	writeCloseErr  error
	done           *done.Instance
	onClose        io.Closer
	// datagrams marks a connection for a UDP destination, whose every buffer
	// is a datagram.
	datagrams bool
	drops     net.DropLog
	local     net.Addr
	remote    net.Addr
}

func (c *Connection) Read(b []byte) (int, error) {
	if !c.datagrams {
		return c.reader.Read(b)
	}
	if len(b) == 0 {
		// no datagram but an empty one fits: drop none for such a read
		return 0, nil
	}
	// A read without bytes or an error only dropped datagrams.
	for {
		if n, err := c.reader.Read(b); n > 0 || err != nil {
			return n, err
		}
	}
}

// splitFirstDatagram copies the first datagram of mb that p holds into p and
// returns the datagrams after it. It drops a datagram longer than p, where
// buf.SplitFirstBytes copies its start as a UDP socket does, without a sign of
// the cut: no reader of the connection can tell that start from a whole
// datagram. It skips an empty one.
func (c *Connection) splitFirstDatagram(mb buf.MultiBuffer, p []byte) (buf.MultiBuffer, int) {
	for {
		var datagram *buf.Buffer
		mb, datagram = buf.SplitFirst(mb)
		if datagram == nil {
			return mb, 0
		}
		size := int(datagram.Len())
		if size == 0 || size > len(p) {
			datagram.Release()
			if size > 0 && c.drops.Due() {
				errors.LogDebug(context.Background(), "dropped a UDP datagram of ", size, " bytes, longer than the ", len(p), " bytes a read takes")
			}
			continue
		}
		copy(p, datagram.Bytes())
		datagram.Release()
		return mb, size
	}
}

// ReadMultiBuffer implements buf.Reader.
func (c *Connection) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return c.reader.ReadMultiBuffer()
}

// Write implements net.Conn.Write().
func (c *Connection) Write(b []byte) (int, error) {
	if c.done.Done() {
		return 0, io.ErrClosedPipe
	}

	l := len(b)
	if c.datagrams && l > buf.Size {
		// A datagram stays in one buffer: split into regular ones, its rest
		// would go on as a datagram of its own.
		datagram := buf.NewWithSize(int32(l))
		common.Must2(datagram.Write(b))
		return l, c.writer.WriteMultiBuffer(buf.MultiBuffer{datagram})
	}
	mb := make(buf.MultiBuffer, 0, l/buf.Size+1)
	mb = buf.MergeBytes(mb, b)
	return l, c.writer.WriteMultiBuffer(mb)
}

func (c *Connection) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if c.done.Done() {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}

	return c.writer.WriteMultiBuffer(mb)
}

func (c *Connection) CloseWrite() error {
	c.writeCloseOnce.Do(func() {
		if c.writeCloser != nil {
			c.writeCloseErr = c.writeCloser.Close()
		} else {
			c.writeCloseErr = common.Close(c.writer)
		}
	})
	return c.writeCloseErr
}

// Close implements net.Conn.Close().
func (c *Connection) Close() error {
	common.Must(c.done.Close())
	common.Interrupt(c.reader)
	_ = c.CloseWrite()
	if c.onClose != nil {
		return c.onClose.Close()
	}

	return nil
}

// LocalAddr implements net.Conn.LocalAddr().
func (c *Connection) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr implements net.Conn.RemoteAddr().
func (c *Connection) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline implements net.Conn.SetDeadline().
func (c *Connection) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline().
func (c *Connection) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline().
func (c *Connection) SetWriteDeadline(t time.Time) error {
	return nil
}
