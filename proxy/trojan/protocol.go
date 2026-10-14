package trojan

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

var (
	crlf = []byte{'\r', '\n'}

	addrParser = protocol.NewAddressParser(
		protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
		protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
		protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
	)
)

const (
	// maxLength is the largest datagram the writer sends: an older Xray
	// reader ends the session on a larger one.
	maxLength = 8192
	// maxPacketHeader is the longest header of a datagram: a domain
	// address, the port, the length and CRLF.
	maxPacketHeader = 1 + 1 + 255 + 2 + 2 + 2

	commandTCP byte = 1
	commandUDP byte = 3
)

// ConnWriter is TCP Connection Writer Wrapper for trojan protocol
type ConnWriter struct {
	io.Writer
	Target     net.Destination
	Account    *MemoryAccount
	headerSent bool
}

// Write implements io.Writer
func (c *ConnWriter) Write(p []byte) (n int, err error) {
	if !c.headerSent {
		if err := c.writeHeader(); err != nil {
			return 0, errors.New("failed to write request header").Base(err)
		}
	}

	return c.Writer.Write(p)
}

// WriteMultiBuffer implements buf.Writer
func (c *ConnWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	for _, b := range mb {
		if !b.IsEmpty() {
			if _, err := c.Write(b.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *ConnWriter) writeHeader() error {
	buffer := buf.StackNew()
	defer buffer.Release()

	command := commandTCP
	if c.Target.Network == net.Network_UDP {
		command = commandUDP
	}

	if _, err := buffer.Write(c.Account.Key); err != nil {
		return err
	}
	if _, err := buffer.Write(crlf); err != nil {
		return err
	}
	if err := buffer.WriteByte(command); err != nil {
		return err
	}
	if err := addrParser.WriteAddressPort(&buffer, c.Target.Address, c.Target.Port); err != nil {
		return err
	}
	if _, err := buffer.Write(crlf); err != nil {
		return err
	}

	_, err := c.Writer.Write(buffer.Bytes())
	if err == nil {
		c.headerSent = true
	}

	return err
}

// PacketWriter UDP Connection Writer Wrapper for trojan protocol
type PacketWriter struct {
	io.Writer
	Target net.Destination
}

// WriteMultiBuffer implements buf.Writer. It drops a datagram above
// maxLength, on which an older Xray reader ends the session, as the VLESS and
// VMess writers drop theirs.
func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		if b.Len() > maxLength {
			b.Release()
			continue
		}
		target := &w.Target
		if b.UDP != nil {
			target = b.UDP
		}
		if _, err := w.writePacket(b.Bytes(), *target); err != nil {
			b.Release()
			buf.ReleaseMulti(mb)
			return err
		}
		b.Release()
	}
	return nil
}

// writePacket writes the datagram in one Write, its header and payload in one
// buffer, which a long payload with its header would overflow if regular.
func (w *PacketWriter) writePacket(payload []byte, dest net.Destination) (int, error) {
	if len(payload) > buf.Size-maxPacketHeader {
		buffer := buf.NewWithSize(int32(maxPacketHeader + len(payload)))
		defer buffer.Release()
		return w.writePacketTo(buffer, payload, dest)
	}
	buffer := buf.StackNew()
	defer buffer.Release()
	return w.writePacketTo(&buffer, payload, dest)
}

func (w *PacketWriter) writePacketTo(buffer *buf.Buffer, payload []byte, dest net.Destination) (int, error) {
	length := len(payload)
	lengthBuf := [2]byte{}
	binary.BigEndian.PutUint16(lengthBuf[:], uint16(length))
	if err := addrParser.WriteAddressPort(buffer, dest.Address, dest.Port); err != nil {
		return 0, err
	}
	if _, err := buffer.Write(lengthBuf[:]); err != nil {
		return 0, err
	}
	if _, err := buffer.Write(crlf); err != nil {
		return 0, err
	}
	if _, err := buffer.Write(payload); err != nil {
		return 0, err
	}
	_, err := w.Write(buffer.Bytes())
	if err != nil {
		return 0, err
	}

	return length, nil
}

// ConnReader is TCP Connection Reader Wrapper for trojan protocol
type ConnReader struct {
	io.Reader
	Target       net.Destination
	Flow         string
	headerParsed bool
}

// ParseHeader parses the trojan protocol header
func (c *ConnReader) ParseHeader() error {
	var crlf [2]byte
	var command [1]byte
	var hash [56]byte
	if _, err := io.ReadFull(c.Reader, hash[:]); err != nil {
		return errors.New("failed to read user hash").Base(err)
	}

	if _, err := io.ReadFull(c.Reader, crlf[:]); err != nil {
		return errors.New("failed to read crlf").Base(err)
	}

	if _, err := io.ReadFull(c.Reader, command[:]); err != nil {
		return errors.New("failed to read command").Base(err)
	}

	network := net.Network_TCP
	if command[0] == commandUDP {
		network = net.Network_UDP
	}

	addr, port, err := addrParser.ReadAddressPort(nil, c.Reader)
	if err != nil {
		return errors.New("failed to read address and port").Base(err)
	}
	c.Target = net.Destination{Network: network, Address: addr, Port: port}

	if _, err := io.ReadFull(c.Reader, crlf[:]); err != nil {
		return errors.New("failed to read crlf").Base(err)
	}

	c.headerParsed = true
	return nil
}

// Read implements io.Reader
func (c *ConnReader) Read(p []byte) (int, error) {
	if !c.headerParsed {
		if err := c.ParseHeader(); err != nil {
			return 0, err
		}
	}

	return c.Reader.Read(p)
}

// ReadMultiBuffer implements buf.Reader
func (c *ConnReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, err := b.ReadFrom(c)
	return buf.MultiBuffer{b}, err
}

// PacketReader is UDP Connection Reader Wrapper for trojan protocol
type PacketReader struct {
	io.Reader
}

// ReadMultiBuffer implements buf.Reader. It returns the next datagram whole,
// in a buffer of its own: a peer may send one above maxLength, which the
// writer does not, and the outbound sends it as it came.
func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	addr, port, err := addrParser.ReadAddressPort(nil, r)
	if err != nil {
		return nil, errors.New("failed to read address and port").Base(err)
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, errors.New("failed to read payload length").Base(err)
	}

	length := int32(binary.BigEndian.Uint16(lengthBuf[:]))

	var crlf [2]byte
	if _, err := io.ReadFull(r, crlf[:]); err != nil {
		return nil, errors.New("failed to read crlf").Base(err)
	}

	if length == 0 {
		return nil, nil
	}
	var b *buf.Buffer
	if length > buf.Size {
		b = buf.NewWithSize(length)
	} else {
		b = buf.New()
	}
	dest := net.UDPDestination(addr, port)
	b.UDP = &dest
	if _, err := b.ReadFullFrom(r, length); err != nil {
		b.Release()
		return nil, errors.New("failed to read payload").Base(err)
	}
	return buf.MultiBuffer{b}, nil
}
