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

const (
	maxReplayBytes = 2 * 1024 * 1024
	// defaultReplayTimeout bounds a single replay onto a replacement stream.
	// Generous enough not to abort a slow but healthy carrier, finite so a
	// stalled one cannot pin writeMu for the session's lifetime.
	defaultReplayTimeout = 30 * time.Second
)

type streamResponseError struct{ message string }

func (e *streamResponseError) Error() string { return e.message }

type retryConn struct {
	ctx           context.Context
	opener        func(context.Context) (net.Conn, error)
	replayTimeout time.Duration

	readMu   sync.Mutex
	writeMu  sync.Mutex
	stateMu  sync.Mutex
	conn     net.Conn
	replay   []byte
	replaced chan struct{}
	// closeSignal releases a reader parked for a replacement. c.replaced alone
	// is not enough: it is only signalled by a successful replaceLocked, so a
	// reader waiting behind a writer that never retries has no other wakeup
	// than context cancellation, which a long-lived inbound context never
	// delivers. Closed exactly once, guarded by the c.closed early return.
	closeSignal chan struct{}

	confirmed     bool
	replayAllowed bool
	retried       bool
	closed        bool
}

func newRetryConn(ctx context.Context, initial net.Conn, opener func(context.Context) (net.Conn, error)) *retryConn {
	return &retryConn{
		ctx:           ctx,
		opener:        opener,
		replayTimeout: defaultReplayTimeout,
		conn:          initial,
		replayAllowed: true,
		replaced:      make(chan struct{}, 1),
		closeSignal:   make(chan struct{}),
	}
}

// replayTo re-sends the buffered payload on a replacement stream under a
// bounded deadline.
//
// Without one this write is unbounded while holding writeMu, and Close cannot
// rescue it: mplsmux.Stream.Close takes the same stream writeMu that
// Stream.Write holds for its whole duration (stream.go:192, stream.go:232), so
// it serializes behind the stalled replay instead of interrupting it. A stalled
// carrier would then pin this connection and up to maxReplayBytes of replay
// until the session died.
func (c *retryConn) replayTo(connection net.Conn, replay []byte) error {
	if len(replay) == 0 {
		return nil
	}
	_ = connection.SetWriteDeadline(time.Now().Add(c.replayTimeout))
	err := writeFull(connection, replay)
	_ = connection.SetWriteDeadline(time.Time{})
	return err
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
	if c.closed || c.conn != failed || c.confirmed || c.retried || !c.replayAllowed {
		current := c.conn
		c.stateMu.Unlock()
		if current == nil {
			return nil, nil, net.ErrClosed
		}
		return nil, nil, errors.New("stream replay is unavailable")
	}
	c.retried = true
	c.replayAllowed = false
	replay := c.replay
	c.replay = nil
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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

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
		if replayErr := c.replayTo(replacement, replay); replayErr != nil {
			_ = replacement.Close()
			return total, replayErr
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
	err := readStreamResponse(connection)
	if err != nil {
		var rejected *streamResponseError
		if errors.As(err, &rejected) {
			return err
		}
		current, currentErr := c.current()
		if currentErr != nil {
			return err
		}
		if current != connection {
			connection = current
		} else if c.writeMu.TryLock() {
			replacement, replay, retryErr := c.replaceLocked(connection)
			if retryErr != nil {
				c.writeMu.Unlock()
				return err
			}
			connection = replacement
			go func() {
				if replayErr := c.replayTo(replacement, replay); replayErr != nil {
					_ = replacement.Close()
				}
				c.writeMu.Unlock()
			}()
		} else {
			select {
			case <-c.replaced:
				connection, currentErr = c.current()
				if currentErr != nil || connection == nil {
					return err
				}
			case <-c.closeSignal:
				return err
			case <-c.ctx.Done():
				return c.ctx.Err()
			}
		}
		if err := readStreamResponse(connection); err != nil {
			return err
		}
	}
	c.stateMu.Lock()
	if c.conn == connection {
		c.confirmed = true
		c.replay = nil
	}
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
	connection := c.conn
	c.conn = nil
	c.replay = nil
	close(c.closeSignal)
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
