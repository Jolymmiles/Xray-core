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
	readHeader    [4]byte
	readPayload   int
	readPadding   int64
	writeMu       sync.Mutex
	writtenFrames int
}

func newPaddingConn(connection net.Conn) net.Conn {
	return newPaddingConnWithGenerator(connection, randomPaddingLength)
}

func newPaddingConnWithGenerator(connection net.Conn, generator func() int) *paddingConn {
	return &paddingConn{Conn: connection, paddingLength: generator}
}

// crypto/rand.Read cannot fail on Go 1.24 and later: a broken system source
// panics rather than returning an error, so neither padding length nor padding
// content has a degraded fallback to pick.
func randomPaddingLength() int {
	var value [1]byte
	rand.Read(value[:])
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
		// The header already announces the padding length, so constant filler
		// would add a recognisable pattern instead of hiding one.
		rand.Read(frame[4+partSize:])
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
		if c.readPayload > 0 {
			readSize := len(destination)
			if readSize > c.readPayload {
				readSize = c.readPayload
			}
			n, err := c.Conn.Read(destination[:readSize])
			c.readPayload -= n
			return n, err
		}
		if c.readPadding > 0 {
			discardSize := len(destination)
			if int64(discardSize) > c.readPadding {
				discardSize = int(c.readPadding)
			}
			discarded, err := c.Conn.Read(destination[:discardSize])
			c.readPadding -= int64(discarded)
			if err != nil {
				return 0, err
			}
			if discarded == 0 {
				return 0, nil
			}
			continue
		}
		if c.readFrames >= paddingFrameCount {
			return c.Conn.Read(destination)
		}
		if _, err := io.ReadFull(c.Conn, c.readHeader[:]); err != nil {
			return 0, err
		}
		c.readPayload = int(binary.BigEndian.Uint16(c.readHeader[0:2]))
		c.readPadding = int64(binary.BigEndian.Uint16(c.readHeader[2:4]))
		c.readFrames++
	}
}

func (c *paddingConn) SetDeadline(deadline time.Time) error {
	return c.Conn.SetDeadline(deadline)
}

var _ net.Conn = (*paddingConn)(nil)
