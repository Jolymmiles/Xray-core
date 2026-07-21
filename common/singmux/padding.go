// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const paddingFrameCount = 16

type paddingConn struct {
	net.Conn
	paddingLength func() int

	readMu        sync.Mutex
	readFrames    int
	readPayload   []byte
	readOffset    int
	writeMu       sync.Mutex
	writtenFrames int
}

func newPaddingConn(connection net.Conn) net.Conn {
	return newPaddingConnWithGenerator(connection, randomPaddingLength)
}

func newPaddingConnWithGenerator(connection net.Conn, generator func() int) *paddingConn {
	return &paddingConn{Conn: connection, paddingLength: generator}
}

func randomPaddingLength() int {
	var value [1]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0
	}
	return int(value[0])
}

func (c *paddingConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(payload) != 0 {
		if c.writtenFrames >= paddingFrameCount {
			n, err := c.Conn.Write(payload)
			written += n
			return written, err
		}
		partSize := len(payload)
		if partSize > maxWirePayload {
			partSize = maxWirePayload
		}
		paddingSize := c.paddingLength()
		if paddingSize < 0 || paddingSize > maxWirePayload {
			return written, errors.New("generated padding length is outside 0..65535")
		}
		frame := make([]byte, 4+partSize+paddingSize)
		binary.BigEndian.PutUint16(frame[0:2], uint16(partSize))
		binary.BigEndian.PutUint16(frame[2:4], uint16(paddingSize))
		copy(frame[4:], payload[:partSize])
		if err := writeFull(c.Conn, frame); err != nil {
			return written, err
		}
		written += partSize
		payload = payload[partSize:]
		c.writtenFrames++
	}
	return written, nil
}

func (c *paddingConn) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.readOffset < len(c.readPayload) {
			n := copy(destination, c.readPayload[c.readOffset:])
			c.readOffset += n
			if c.readOffset == len(c.readPayload) {
				c.readPayload = nil
				c.readOffset = 0
			}
			return n, nil
		}
		if c.readFrames >= paddingFrameCount {
			return c.Conn.Read(destination)
		}
		var header [4]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		payloadSize := int(binary.BigEndian.Uint16(header[0:2]))
		paddingSize := int64(binary.BigEndian.Uint16(header[2:4]))
		c.readPayload = make([]byte, payloadSize)
		if _, err := io.ReadFull(c.Conn, c.readPayload); err != nil {
			c.readPayload = nil
			return 0, err
		}
		if _, err := io.CopyN(io.Discard, c.Conn, paddingSize); err != nil {
			c.readPayload = nil
			return 0, err
		}
		c.readFrames++
	}
}

func (c *paddingConn) SetDeadline(deadline time.Time) error {
	return c.Conn.SetDeadline(deadline)
}

var _ net.Conn = (*paddingConn)(nil)
