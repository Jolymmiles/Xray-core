package splithttp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	reality "github.com/xtls/reality"
)

// shapeConn groups the server's first frames into the target's observed
// TLS records and keeps the local stream and connection windows.
//
// Dropping MAX_HEADER_LIST_SIZE leaves it unannounced, which is advisory;
// dropping ENABLE_CONNECT_PROTOCOL leaves extended CONNECT off, which XHTTP
// does not use.

const (
	frameHeaderLen  = 9
	frameSettings   = 0x4
	frameWindowUpd  = 0x8
	settingMaxConc  = 0x3
	settingInitWin  = 0x4
	settingMaxFrame = 0x5
)

// shapeWait is how long the server's SETTINGS waits for the WINDOW_UPDATE
// that goes with it.
const shapeWait = 50 * time.Millisecond

// A mixed record can wait a little longer for the first HTTP response.
const shapeReplyWait = 150 * time.Millisecond

type shapeListener struct {
	net.Listener
	startupGrant uint32
}

func (l *shapeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	shaped := &shapeConn{Conn: conn}
	if writer, ok := conn.(h2StartupConn); ok {
		shaped.writer = writer
		shaped.profile = writer.H2StartupRecords()
	}
	if len(shaped.profile) == 0 {
		return conn, nil
	}
	if shaped.omitsStartupWindow() {
		shaped.startupGrant = l.startupGrant
	}
	return shaped, nil
}

type shapeConn struct {
	net.Conn
	mu    sync.Mutex
	state int // 0 before the first write, 1 holding SETTINGS, 2 passing through
	timer *time.Timer
	err   error

	profile []reality.H2StartupRecord
	writer  h2StartupConn
	frames  [4][]byte

	startupGrant uint32
	heldGrant    uint32
	grantParser  frameParser
}

type h2StartupConn interface {
	H2StartupRecords() []reality.H2StartupRecord
	WritePaddedAppRecord([]byte, int) (int, error)
}

// recordOverhead is what a TLS 1.3 record adds to its content: the header,
// the content type and the AEAD tag.
const recordOverhead = 5 + 1 + 16

func (c *shapeConn) omitsStartupWindow() bool {
	return len(c.profile) > 0 && !slices.ContainsFunc(c.profile, func(record reality.H2StartupRecord) bool {
		return slices.Contains(record.Frames, reality.H2WindowUpdate)
	})
}

func (c *shapeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case 0:
		settings, rest, ok := splitFrame(b, frameSettings)
		if !ok || len(c.profile) == 0 {
			c.state = 2
			c.startupGrant = 0
			return c.Conn.Write(b)
		}
		c.frames[reality.H2Settings] = bytes.Clone(settings)
		c.state = 1
		if err := c.writeStartup(rest, false); err != nil {
			return 0, err
		}
		if c.state == 1 {
			c.waitForStartup()
		}
		return len(b), nil
	case 1:
		return len(b), c.writeStartup(b, false)
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.writeAfterStartup(b)
}

func (c *shapeConn) waitForStartup() {
	wait := shapeWait
	if len(c.profile) > 0 && c.profile[len(c.profile)-1].ResponseBytes != 0 {
		wait = shapeReplyWait
	}
	c.timer = time.AfterFunc(wait, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.state == 1 {
			c.err = c.writeStartup(nil, true)
		}
	})
}

// writeStartup collects the local control frames and emits each target record
// as soon as its frames are available. Unexpected frames end shaping.
func (c *shapeConn) writeStartup(b []byte, force bool) error {
	for len(b) >= frameHeaderLen {
		n := frameSize(b)
		kind := startupKind(b)
		if kind == 0 || n > len(b) || c.frames[kind] != nil {
			break
		}
		c.frames[kind] = bytes.Clone(b[:n])
		b = b[n:]
	}
	replyPrepared := false
	for len(c.profile) > 0 {
		record := c.profile[0]
		controlLength := record.Length - record.ResponseBytes
		room := controlLength - recordOverhead
		ready := true
		for _, kind := range record.Frames {
			frame := c.frames[kind]
			ready = ready && frame != nil
			if kind != reality.H2Settings {
				room -= len(frame)
			}
		}
		if !ready {
			break
		}
		if record.ResponseBytes != 0 && len(b) == 0 && !force {
			break
		}
		var payload []byte
		for _, kind := range record.Frames {
			frame := c.frames[kind]
			if kind == reality.H2Settings {
				frame = fitSettings(frame, room)
			}
			payload = append(payload, frame...)
		}
		if len(payload)+recordOverhead > controlLength {
			force = true
			break
		}
		length := controlLength
		for _, kind := range record.Frames {
			c.frames[kind] = nil
		}
		if record.ResponseBytes != 0 && startsH2Reply(b) {
			// Run the upload credit filter on the whole plaintext before
			// splitting it across TLS records, so it keeps frame boundaries.
			b = c.afterStartupBytes(c.startupRemainder(b))
			replyPrepared = true
			if startsH2Reply(b) {
				n := min(len(b), record.Length-recordOverhead-len(payload))
				payload = append(payload, b[:n]...)
				b = b[n:]
				length = record.Length
			}
		}
		if n, err := c.writer.WritePaddedAppRecord(payload, length); err != nil {
			c.err = err
		} else if n != len(payload) {
			c.err = io.ErrShortWrite
		}
		if c.err != nil {
			c.state = 2
			return c.err
		}
		c.profile = c.profile[1:]
	}
	if len(c.profile) > 0 && !force && len(b) == 0 {
		return nil
	}
	if len(c.profile) > 0 {
		c.startupGrant = 0
	}
	c.state = 2
	if c.timer != nil {
		c.timer.Stop()
	}
	rest := c.startupRemainder(b)
	if len(rest) == 0 {
		return nil
	}
	if replyPrepared {
		_, err := c.Conn.Write(rest)
		return err
	}
	_, err := c.writeAfterStartup(rest)
	return err
}

func (c *shapeConn) startupRemainder(b []byte) []byte {
	var rest []byte
	for _, kind := range []reality.H2StartupFrame{reality.H2Settings, reality.H2WindowUpdate, reality.H2SettingsAck} {
		rest = append(rest, c.frames[kind]...)
		c.frames[kind] = nil
	}
	return append(rest, b...)
}

func startsH2Reply(b []byte) bool {
	return len(b) >= frameHeaderLen && b[3] == h2Headers && binary.BigEndian.Uint32(b[5:9])&0x7fffffff != 0
}

// When the target starts at the default connection window, hold the local
// bootstrap grant until the server returns credit for consumed request data.
func (c *shapeConn) writeAfterStartup(b []byte) (int, error) {
	out := c.afterStartupBytes(b)
	if len(out) != 0 {
		if n, err := c.Conn.Write(out); err != nil {
			return 0, err
		} else if n != len(out) {
			return 0, io.ErrShortWrite
		}
	}
	return len(b), nil
}

func (c *shapeConn) afterStartupBytes(b []byte) []byte {
	if c.startupGrant == 0 && c.heldGrant == 0 && c.grantParser.atBoundary() {
		return b
	}
	return c.grantParser.feed(b, nil, c)
}

func (c *shapeConn) frame(h2Frame) bool         { return false }
func (c *shapeConn) boundary(out []byte) []byte { return out }

func (c *shapeConn) control(f h2Frame, header, payload, out []byte) []byte {
	if f.typ == h2WindowUpdate && f.stream == 0 {
		inc := binary.BigEndian.Uint32(payload) & h2MaxWindow
		if c.startupGrant != 0 {
			grant := c.startupGrant
			c.startupGrant = 0
			if inc == grant {
				c.heldGrant = inc
				return out
			}
		}
		if c.heldGrant != 0 && inc != 0 {
			extra := min(c.heldGrant, h2MaxWindow-inc)
			c.heldGrant -= extra
			return binary.BigEndian.AppendUint32(append(out, header...), inc+extra)
		}
	}
	return append(append(out, header...), payload...)
}

func startupKind(b []byte) reality.H2StartupFrame {
	if binary.BigEndian.Uint32(b[5:9])&0x7fffffff != 0 {
		return 0
	}
	if b[3] == frameWindowUpd && b[4] == 0 && frameSize(b) == frameHeaderLen+4 {
		return reality.H2WindowUpdate
	}
	if b[3] == frameSettings && b[4] == 1 && frameSize(b) == frameHeaderLen {
		return reality.H2SettingsAck
	}
	return 0
}

// splitFrame returns the frame b starts with if it is of type typ, not an
// acknowledgement, and the bytes after it.
func splitFrame(b []byte, typ byte) (frame, rest []byte, ok bool) {
	if len(b) < frameHeaderLen || b[3] != typ || b[4]&0x1 != 0 {
		return nil, b, false
	}
	n := frameSize(b)
	if n > len(b) {
		return nil, b, false
	}
	return b[:n], b[n:], true
}

func frameSize(b []byte) int {
	return frameHeaderLen + (int(b[0])<<16 | int(b[1])<<8 | int(b[2]))
}

// settingsKept are the parameters kept first when SETTINGS has to shrink:
// those that shape flow control, then the rest of what nginx sends.
var settingsKept = []uint16{settingInitWin, settingMaxConc, settingMaxFrame}

// fitSettings removes settings to fit the measured record.
// The advertised stream window and concurrency limit stay in the frame.
func fitSettings(settings []byte, room int) []byte {
	if len(settings) <= room {
		return settings
	}
	selected := make(map[uint16]bool)
	capacity := (room - frameHeaderLen) / 6
	for _, id := range settingsKept {
		if len(selected) < capacity || id == settingInitWin || id == settingMaxConc {
			selected[id] = true
		}
	}
	for p := frameHeaderLen; p+6 <= len(settings); p += 6 {
		id := binary.BigEndian.Uint16(settings[p:])
		if len(selected) < capacity {
			selected[id] = true
		}
	}
	out := append([]byte(nil), settings[:frameHeaderLen]...)
	for p := frameHeaderLen; p+6 <= len(settings); p += 6 {
		if selected[binary.BigEndian.Uint16(settings[p:])] {
			out = append(out, settings[p:p+6]...)
		}
	}
	n := len(out) - frameHeaderLen
	out[0], out[1], out[2] = byte(n>>16), byte(n>>8), byte(n)
	return out
}

// ackConn writes the acknowledgement of the server's SETTINGS in a record of
// its own, as Chrome does; Go's client writes it with the WINDOW_UPDATE
// that follows.
type ackConn struct {
	net.Conn
}

func (c *ackConn) Write(b []byte) (int, error) {
	at := -1
	for p := 0; p+frameHeaderLen <= len(b); {
		n := frameSize(b[p:])
		if p+n > len(b) {
			break
		}
		if b[p+3] == frameSettings && b[p+4]&0x1 != 0 {
			at = p
			break
		}
		p += n
	}
	if at < 0 || len(b) == frameHeaderLen {
		return c.Conn.Write(b)
	}
	written := 0
	for _, part := range [][]byte{b[:at], b[at : at+frameHeaderLen], b[at+frameHeaderLen:]} {
		if len(part) == 0 {
			continue
		}
		n, err := c.Conn.Write(part)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}
