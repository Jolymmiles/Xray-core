// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const maxReplayBytes = 2 * 1024 * 1024

type streamResponseError struct{ message string }

func (e *streamResponseError) Error() string { return e.message }

type retryConn struct {
	ctx    context.Context
	opener func(context.Context) (net.Conn, error)

	readMu      sync.Mutex
	writePermit chan struct{}
	stateMu     sync.Mutex
	conn        net.Conn
	replay      []byte
	replaced    chan struct{}

	confirmed     bool
	replayAllowed bool
	retries       int
	maxRetries    int
	halfClose     bool
	writeClosed   bool
	closed        bool
}

func newRetryConn(ctx context.Context, initial net.Conn, opener func(context.Context) (net.Conn, error)) *retryConn {
	return newBoundedRetryConn(ctx, initial, opener, 1)
}

func newBoundedRetryConn(ctx context.Context, initial net.Conn, opener func(context.Context) (net.Conn, error), maxRetries int) *retryConn {
	if maxRetries < 1 {
		maxRetries = 1
	}
	halfClose := false
	if _, ok := initial.(interface{ CloseWrite() error }); ok {
		halfClose = true
		if negotiated, ok := initial.(interface{ LogicalHalfCloseEnabled() bool }); ok {
			halfClose = negotiated.LogicalHalfCloseEnabled()
		}
	}
	connection := &retryConn{
		ctx:           ctx,
		opener:        opener,
		writePermit:   make(chan struct{}, 1),
		conn:          initial,
		replaced:      make(chan struct{}, 1),
		replayAllowed: true,
		maxRetries:    maxRetries,
		halfClose:     halfClose,
	}
	connection.releaseWrite()
	return connection
}

func (c *retryConn) acquireWrite() {
	<-c.writePermit
}

func (c *retryConn) releaseWrite() {
	c.writePermit <- struct{}{}
}

func (c *retryConn) current() (net.Conn, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed || c.conn == nil {
		return nil, net.ErrClosed
	}
	return c.conn, nil
}

func (c *retryConn) remember(payload []byte) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.confirmed || !c.replayAllowed || len(payload) == 0 {
		return
	}
	if len(c.replay)+len(payload) > maxReplayBytes {
		c.replay = nil
		c.replayAllowed = false
		return
	}
	c.replay = append(c.replay, payload...)
}

func (c *retryConn) replaceLocked(failed net.Conn) (net.Conn, []byte, error) {
	c.stateMu.Lock()
	if c.closed || c.conn != failed || c.confirmed || c.retries >= c.maxRetries || !c.replayAllowed {
		current := c.conn
		c.stateMu.Unlock()
		if current == nil {
			return nil, nil, net.ErrClosed
		}
		return nil, nil, errors.New("stream replay is unavailable")
	}
	c.retries++
	if c.retries >= c.maxRetries {
		c.replayAllowed = false
	}
	replay := append([]byte(nil), c.replay...)
	if c.retries >= c.maxRetries {
		c.replay = nil
	}
	c.stateMu.Unlock()

	_ = failed.Close()
	replacement, err := c.opener(c.ctx)
	if err != nil {
		return nil, nil, err
	}
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		_ = replacement.Close()
		return nil, nil, net.ErrClosed
	}
	c.conn = replacement
	c.stateMu.Unlock()
	select {
	case c.replaced <- struct{}{}:
	default:
	}
	return replacement, replay, nil
}

func (c *retryConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	c.acquireWrite()
	defer c.releaseWrite()
	c.stateMu.Lock()
	writeClosed := c.writeClosed
	c.stateMu.Unlock()
	if writeClosed {
		return 0, io.ErrClosedPipe
	}

	total := 0
	for total < len(payload) {
		connection, err := c.current()
		if err != nil {
			return total, err
		}
		n, writeErr := connection.Write(payload[total:])
		if n > 0 {
			c.remember(payload[total : total+n])
			total += n
		}
		if writeErr == nil && n == 0 {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			continue
		}
		replacement, replay, retryErr := c.replaceLocked(connection)
		if retryErr != nil {
			return total, writeErr
		}
		if replayErr := writeFull(replacement, replay); replayErr != nil {
			_ = replacement.Close()
			writeErr = replayErr
			continue
		}
	}
	return total, nil
}

func (c *retryConn) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	connection, err := c.current()
	if err != nil {
		return 0, err
	}
	c.stateMu.Lock()
	confirmed := c.confirmed
	c.stateMu.Unlock()
	if !confirmed {
		if err := c.awaitResponse(connection); err != nil {
			return 0, err
		}
		connection, err = c.current()
		if err != nil {
			return 0, err
		}
	}
	return connection.Read(destination)
}

func (c *retryConn) awaitResponse(connection net.Conn) error {
	for {
		err := readStreamResponse(connection)
		if err == nil {
			c.stateMu.Lock()
			if c.conn == connection {
				c.confirmed = true
				c.replay = nil
			}
			c.stateMu.Unlock()
			return nil
		}
		var rejected *streamResponseError
		if errors.As(err, &rejected) {
			return err
		}
		ownsWrite := false
		select {
		case <-c.replaced:
		case <-c.writePermit:
			ownsWrite = true
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
		current, currentErr := c.current()
		if currentErr != nil {
			if ownsWrite {
				c.releaseWrite()
			}
			return err
		}
		if current != connection {
			if ownsWrite {
				c.releaseWrite()
			}
			connection = current
			continue
		}
		if !ownsWrite {
			select {
			case <-c.writePermit:
				ownsWrite = true
			case <-c.ctx.Done():
				return c.ctx.Err()
			}
			current, currentErr = c.current()
			if currentErr != nil {
				if ownsWrite {
					c.releaseWrite()
				}
				return err
			}
			if current != connection {
				if ownsWrite {
					c.releaseWrite()
				}
				connection = current
				continue
			}
		}
		if !ownsWrite {
			return err
		}
		replacement, replay, retryErr := c.replaceLocked(connection)
		if retryErr != nil {
			c.releaseWrite()
			return err
		}
		connection = replacement
		go func() {
			if replayErr := writeFull(replacement, replay); replayErr != nil {
				_ = replacement.Close()
			}
			c.releaseWrite()
		}()
	}
}

func (c *retryConn) SupportsHalfClose() bool { return c.halfClose }

func (c *retryConn) CloseWrite() error {
	if !c.halfClose {
		return io.ErrClosedPipe
	}
	c.acquireWrite()
	defer c.releaseWrite()
	c.stateMu.Lock()
	if c.closed || c.conn == nil {
		c.stateMu.Unlock()
		return net.ErrClosed
	}
	if c.writeClosed {
		c.stateMu.Unlock()
		return io.ErrClosedPipe
	}
	connection := c.conn
	c.stateMu.Unlock()
	closeWriter, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		return io.ErrClosedPipe
	}
	if err := closeWriter.CloseWrite(); err != nil {
		return err
	}
	c.stateMu.Lock()
	c.writeClosed = true
	c.replayAllowed = false
	c.replay = nil
	c.stateMu.Unlock()
	return nil
}

func (c *retryConn) Close() error {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil
	}
	c.closed = true
	c.writeClosed = true
	connection := c.conn
	c.conn = nil
	c.replay = nil
	c.stateMu.Unlock()
	if connection != nil {
		return connection.Close()
	}
	return nil
}

func (c *retryConn) LocalAddr() net.Addr {
	connection, err := c.current()
	if err != nil {
		return nil
	}
	return connection.LocalAddr()
}

func (c *retryConn) RemoteAddr() net.Addr {
	connection, err := c.current()
	if err != nil {
		return nil
	}
	return connection.RemoteAddr()
}

func (c *retryConn) SetDeadline(deadline time.Time) error {
	connection, err := c.current()
	if err != nil {
		return err
	}
	return connection.SetDeadline(deadline)
}

func (c *retryConn) SetReadDeadline(deadline time.Time) error {
	connection, err := c.current()
	if err != nil {
		return err
	}
	return connection.SetReadDeadline(deadline)
}

func (c *retryConn) SetWriteDeadline(deadline time.Time) error {
	connection, err := c.current()
	if err != nil {
		return err
	}
	return connection.SetWriteDeadline(deadline)
}

var _ net.Conn = (*retryConn)(nil)
