package hysteria

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/apernet/quic-go/quicvarint"
	corebuf "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/hysteria"
)

const (
	// Max length values are for preventing DoS attacks

	MaxAddressLength = 2048
	MaxMessageLength = 2048
	MaxPaddingLength = 4096

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

var tcpAddressBufferPool = sync.Pool{
	New: func() any { return new([MaxAddressLength]byte) },
}

type serverTCPRequest struct {
	buffer      [MaxAddressLength]byte
	varint      [8]byte
	address     serverTCPAddress
	destination xnet.Destination
	link        transport.Link
}

type serverTCPAddress struct {
	owner  *serverTCPRequest
	family xnet.AddressFamily
	length uint16
	ip     [16]byte
}

var serverTCPRequestPool sync.Pool

func (a *serverTCPAddress) IP() stdnet.IP {
	if a.family.IsIPv4() {
		return a.ip[:4]
	}
	return a.ip[:]
}

func (a *serverTCPAddress) Domain() string {
	if !a.family.IsDomain() {
		panic("Calling Domain() on a Hysteria IP address.")
	}
	return unsafe.String(&a.owner.buffer[0], a.length)
}

func (a *serverTCPAddress) Family() xnet.AddressFamily { return a.family }

func (a *serverTCPAddress) String() string {
	if a.family.IsDomain() {
		return unsafe.String(&a.owner.buffer[0], a.length)
	}
	ip := a.NetIPAddr()
	if ip.Is6() {
		return "[" + ip.String() + "]"
	}
	return ip.String()
}

func (a *serverTCPAddress) NetIPAddr() netip.Addr {
	if a.family.IsDomain() {
		return netip.Addr{}
	}
	if a.family.IsIPv4() {
		return netip.AddrFrom4([4]byte(a.ip[:4]))
	}
	return netip.AddrFrom16(a.ip)
}

func acquireServerTCPRequest() *serverTCPRequest {
	request, _ := serverTCPRequestPool.Get().(*serverTCPRequest)
	if request == nil {
		request = new(serverTCPRequest)
		request.address.owner = request
	}
	return request
}

func releaseServerTCPRequest(request *serverTCPRequest) {
	if request == nil {
		return
	}
	request.destination = xnet.Destination{}
	request.link = transport.Link{}
	request.address.family = 0
	request.address.length = 0
	request.address.ip = [16]byte{}
	serverTCPRequestPool.Put(request)
}

func (r *serverTCPRequest) setAddress(host []byte) xnet.Address {
	if len(host) == 0 {
		return xnet.AnyIP
	}
	if first := host[0]; first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' {
		r.address.family = xnet.AddressFamilyDomain
		r.address.length = uint16(len(host))
		return &r.address
	}
	ip, err := netip.ParseAddr(unsafe.String(unsafe.SliceData(host), len(host)))
	if err == nil && ip.Zone() == "" {
		ip = ip.Unmap()
		if ip.Is4() {
			value := ip.As4()
			copy(r.address.ip[:4], value[:])
			r.address.family = xnet.AddressFamilyIPv4
		} else {
			r.address.ip = ip.As16()
			r.address.family = xnet.AddressFamilyIPv6
		}
		return &r.address
	}
	r.address.family = xnet.AddressFamilyDomain
	r.address.length = uint16(len(host))
	return &r.address
}

func (r *serverTCPRequest) parseDestination(address []byte) error {
	if len(address) > 0 && address[0] != '[' {
		if colon, port, ok := parseServerAddressPort(address); ok {
			r.destination = xnet.TCPDestination(r.setAddress(address[:colon]), port)
			return nil
		}
	}
	destination, err := parseServerTCPDestination(string(address))
	if err != nil {
		return err
	}
	r.destination = destination
	return nil
}

func parseServerAddressPort(address []byte) (int, xnet.Port, bool) {
	value := uint32(0)
	multiplier := uint32(1)
	digits := 0
	for index := len(address) - 1; index >= 0; index-- {
		character := address[index]
		if character == ':' {
			if bytes.IndexByte(address[:index], ':') >= 0 || value > 65535 {
				return 0, 0, false
			}
			return index, xnet.Port(value), true
		}
		if character < '0' || character > '9' || digits == 5 {
			return 0, 0, false
		}
		value += uint32(character-'0') * multiplier
		multiplier *= 10
		digits++
	}
	return 0, 0, false
}

func readServerQUICVarint(r io.Reader, byteReader io.ByteReader, scratch *[8]byte) (uint64, error) {
	if byteReader != nil {
		return quicvarint.Read(byteReader)
	}
	if _, err := io.ReadFull(r, scratch[:1]); err != nil {
		return 0, err
	}
	length := 1 << (scratch[0] >> 6)
	if length > 1 {
		if _, err := io.ReadFull(r, scratch[1:length]); err != nil {
			return 0, err
		}
	}
	switch length {
	case 1:
		return uint64(scratch[0] & 0x3f), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(scratch[:2]) & 0x3fff), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(scratch[:4]) & 0x3fffffff), nil
	default:
		return binary.BigEndian.Uint64(scratch[:]) & maxVarInt8, nil
	}
}

func readServerTCPRequest(r io.Reader) (*serverTCPRequest, error) {
	request := acquireServerTCPRequest()
	byteReader, _ := r.(io.ByteReader)
	addrLen, err := readServerQUICVarint(r, byteReader, &request.varint)
	if err != nil {
		releaseServerTCPRequest(request)
		return nil, err
	}
	if addrLen == 0 || addrLen > MaxAddressLength {
		releaseServerTCPRequest(request)
		return nil, errors.New("invalid address length")
	}
	address := request.buffer[:addrLen]
	if _, err = io.ReadFull(r, address); err != nil {
		releaseServerTCPRequest(request)
		return nil, err
	}
	paddingLen, err := readServerQUICVarint(r, byteReader, &request.varint)
	if err != nil {
		releaseServerTCPRequest(request)
		return nil, err
	}
	if paddingLen > MaxPaddingLength {
		releaseServerTCPRequest(request)
		return nil, errors.New("invalid padding length")
	}
	if err := request.parseDestination(address); err != nil {
		releaseServerTCPRequest(request)
		return nil, err
	}
	if paddingLen > 0 {
		paddingBuffer := request.buffer[addrLen:]
		var fallbackBuffer *[MaxAddressLength]byte
		if len(paddingBuffer) == 0 {
			fallbackBuffer = tcpAddressBufferPool.Get().(*[MaxAddressLength]byte)
			paddingBuffer = fallbackBuffer[:]
		}
		for paddingLen > 0 {
			chunkLength := min(uint64(len(paddingBuffer)), paddingLen)
			if _, err = io.ReadFull(r, paddingBuffer[:chunkLength]); err != nil {
				if fallbackBuffer != nil {
					tcpAddressBufferPool.Put(fallbackBuffer)
				}
				releaseServerTCPRequest(request)
				return nil, err
			}
			paddingLen -= chunkLength
		}
		if fallbackBuffer != nil {
			tcpAddressBufferPool.Put(fallbackBuffer)
		}
	}
	return request, nil
}

const maxTCPResponseFrameSize = 1 + 8 + MaxMessageLength + 8 + MaxPaddingLength

var tcpResponseBufferPool = sync.Pool{
	New: func() any { return new([maxTCPResponseFrameSize]byte) },
}

// TCPRequest format:
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPRequest(r io.Reader) (string, error) {
	bReader := quicvarint.NewReader(r)
	addrLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > MaxAddressLength {
		return "", errors.New("invalid address length")
	}
	addrBuffer := tcpAddressBufferPool.Get().(*[MaxAddressLength]byte)
	defer tcpAddressBufferPool.Put(addrBuffer)
	address := addrBuffer[:addrLen]
	_, err = io.ReadFull(r, address)
	if err != nil {
		return "", err
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if paddingLen > MaxPaddingLength {
		return "", errors.New("invalid padding length")
	}
	parsedAddress := string(address)
	if paddingLen > 0 {
		for paddingLen > 0 {
			chunkLength := min(uint64(len(addrBuffer)), paddingLen)
			if _, err = io.ReadFull(r, addrBuffer[:chunkLength]); err != nil {
				return "", err
			}
			paddingLen -= chunkLength
		}
	}
	return parsedAddress, nil
}

func WriteTCPRequest(w io.Writer, addr string) error {
	padding := hysteria.TcpRequestPadding.String()
	paddingLen := len(padding)
	addrLen := len(addr)
	sz := int(quicvarint.Len(uint64(addrLen))) + addrLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	i := varintPut(buf, uint64(addrLen))
	i += copy(buf[i:], addr)
	i += varintPut(buf[i:], uint64(paddingLen))
	copy(buf[i:], padding)
	_, err := w.Write(buf)
	return err
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	bReader := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if msgLen > MaxMessageLength {
		return false, "", errors.New("invalid message length")
	}
	var msgBuf []byte
	// No message is fine
	if msgLen > 0 {
		msgBuf = make([]byte, msgLen)
		_, err = io.ReadFull(r, msgBuf)
		if err != nil {
			return false, "", err
		}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if paddingLen > MaxPaddingLength {
		return false, "", errors.New("invalid padding length")
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return false, "", err
		}
	}
	return status[0] == 0, string(msgBuf), nil
}

func WriteTCPResponse(w io.Writer, ok bool, msg string) error {
	paddingLen, paddingState := hysteria.TcpResponsePadding.LenAndState()
	msgLen := len(msg)
	sz := 1 + int(quicvarint.Len(uint64(msgLen))) + msgLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buffer := tcpResponseBufferPool.Get().(*[maxTCPResponseFrameSize]byte)
	frame := buffer[:sz]
	if ok {
		frame[0] = 0
	} else {
		frame[0] = 1
	}
	i := varintPut(frame[1:], uint64(msgLen))
	i += copy(frame[1+i:], msg)
	i += varintPut(frame[1+i:], uint64(paddingLen))
	hysteria.TcpResponsePadding.FillWithState(frame[1+i:], paddingState)
	_, err := w.Write(frame)
	tcpResponseBufferPool.Put(buffer)
	return err
}

func writeTCPResponseOK(w io.Writer) error {
	paddingLen, paddingState := hysteria.TcpResponsePadding.LenAndState()
	buffer := tcpResponseBufferPool.Get().(*[maxTCPResponseFrameSize]byte)
	frame := buffer[:4+paddingLen]
	frame[0] = 0
	frame[1] = 0
	frame[2] = byte(paddingLen>>8) | 0x40
	frame[3] = byte(paddingLen)
	hysteria.TcpResponsePadding.FillWithState(frame[4:], paddingState)
	_, err := w.Write(frame)
	tcpResponseBufferPool.Put(buffer)
	return err
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Data...

type UDPMessage struct {
	SessionID uint32 // 4
	PacketID  uint16 // 2
	FragID    uint8  // 1
	FragCount uint8  // 1
	Addr      string // varint + bytes
	Data      []byte
}

func (m *UDPMessage) HeaderSize() int {
	lAddr := len(m.Addr)
	return 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(lAddr))) + lAddr
}

func (m *UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m *UDPMessage) Serialize(buf []byte) int {
	return m.serializeAddress(buf, []byte(m.Addr))
}

func (m *UDPMessage) serializeAddress(buf []byte, address []byte) int {
	// Make sure the buffer is big enough
	headerSize := 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(len(address)))) + len(address)
	if len(buf) < headerSize+len(m.Data) {
		return -1
	}
	// binary.BigEndian.PutUint32(buf, m.SessionID)
	binary.BigEndian.PutUint16(buf[4:], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	i := varintPut(buf[8:], uint64(len(address)))
	i += copy(buf[8+i:], address)
	i += copy(buf[8+i:], m.Data)
	return 8 + i
}

func ParseUDPMessage(msg []byte) (*UDPMessage, error) {
	parsed := new(UDPMessage)
	if err := parseUDPMessage(msg, parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func parseUDPMessage(msg []byte, parsed *UDPMessage) error {
	address, err := parseUDPMessageFields(msg, parsed)
	if err != nil {
		return err
	}
	parsed.Addr = string(address)
	return nil
}

func parseUDPMessageFields(msg []byte, parsed *UDPMessage) ([]byte, error) {
	if len(msg) < 9 {
		return nil, io.ErrUnexpectedEOF
	}
	var lAddr uint64
	n := 1
	if first := msg[8]; first < 0x40 {
		lAddr = uint64(first)
	} else {
		var err error
		lAddr, n, err = quicvarint.Parse(msg[8:])
		if err != nil {
			return nil, err
		}
	}
	if lAddr == 0 || lAddr > MaxMessageLength {
		return nil, errors.New("invalid address length")
	}
	bs := msg[8+n:]
	if len(bs) <= int(lAddr) {
		// We use <= instead of < here as we expect at least one byte of data after the address
		return nil, errors.New("invalid message length")
	}
	*parsed = UDPMessage{
		SessionID: binary.BigEndian.Uint32(msg),
		PacketID:  binary.BigEndian.Uint16(msg[4:]),
		FragID:    msg[6],
		FragCount: msg[7],
		Data:      bs[lAddr:],
	}
	return bs[:lAddr], nil
}

// varintPut is like quicvarint.Append, but instead of appending to a slice,
// it writes to a fixed-size buffer. Returns the number of bytes written.
func varintPut(b []byte, i uint64) int {
	if i <= maxVarInt1 {
		b[0] = uint8(i)
		return 1
	}
	if i <= maxVarInt2 {
		b[0] = uint8(i>>8) | 0x40
		b[1] = uint8(i)
		return 2
	}
	if i <= maxVarInt4 {
		b[0] = uint8(i>>24) | 0x80
		b[1] = uint8(i >> 16)
		b[2] = uint8(i >> 8)
		b[3] = uint8(i)
		return 4
	}
	if i <= maxVarInt8 {
		b[0] = uint8(i>>56) | 0xc0
		b[1] = uint8(i >> 48)
		b[2] = uint8(i >> 40)
		b[3] = uint8(i >> 32)
		b[4] = uint8(i >> 24)
		b[5] = uint8(i >> 16)
		b[6] = uint8(i >> 8)
		b[7] = uint8(i)
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}

func FragUDPMessage(m *UDPMessage, maxSize int) []UDPMessage {
	if m.Size() <= maxSize {
		return []UDPMessage{*m}
	}
	fullPayload := m.Data
	maxPayloadSize := maxSize - m.HeaderSize()
	if maxPayloadSize <= 0 {
		return nil
	}
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + maxPayloadSize - 1) / maxPayloadSize) // round up
	frags := make([]UDPMessage, fragCount)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := *m
		frag.FragID = fragID
		frag.FragCount = fragCount
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags
}

// Defragger handles the defragmentation of UDP messages.
// The current implementation can only handle one packet ID at a time.
// If another packet arrives before a packet has received all fragments
// in their entirety, any previous state is discarded.
type Defragger struct {
	pktID     uint16
	frags     [][]byte
	small     [8][]byte
	fragCount uint8
	count     uint8
	size      int // data size
	storage   *[corebuf.Size]byte
	used      int
}

var defragmentStoragePool = sync.Pool{
	New: func() any { return new([corebuf.Size]byte) },
}

func (d *Defragger) Feed(m *UDPMessage) *UDPMessage {
	if m.FragCount <= 1 {
		return m
	}
	if !d.storeFragment(m) {
		return nil
	}
	return d.assemble(m, make([]byte, d.size))
}

func (d *Defragger) storeFragment(m *UDPMessage) bool {
	if m.FragID >= m.FragCount {
		return false
	}
	if m.PacketID != d.pktID || m.FragCount != d.fragCount {
		// new message, clear previous state
		d.pktID = m.PacketID
		d.fragCount = m.FragCount
		if int(m.FragCount) <= len(d.small) {
			clear(d.small[:])
			d.frags = nil
			d.small[m.FragID] = m.Data
		} else {
			d.frags = make([][]byte, m.FragCount)
			d.frags[m.FragID] = m.Data
		}
		d.count = 1
		d.size = len(m.Data)
	} else if d.fragment(m.FragID) == nil {
		d.setFragment(m.FragID, m.Data)
		d.count++
		d.size += len(m.Data)
	}
	return d.count == d.fragCount
}

func (d *Defragger) storeClonedFragment(message *UDPMessage) bool {
	if message.PacketID != d.pktID || message.FragCount != d.fragCount {
		d.used = 0
	}
	if d.storage == nil {
		d.storage = defragmentStoragePool.Get().(*[corebuf.Size]byte)
	}
	if len(message.Data) <= len(d.storage)-d.used {
		start := d.used
		d.used += copy(d.storage[start:], message.Data)
		message.Data = d.storage[start:d.used]
	} else {
		message.Data = bytes.Clone(message.Data)
	}
	return d.storeFragment(message)
}

func (d *Defragger) assemble(message *UDPMessage, data []byte) *UDPMessage {
	offset := 0
	for index := range d.fragCount {
		offset += copy(data[offset:], d.fragment(index))
	}
	message.Data = data[:offset]
	message.FragID = 0
	message.FragCount = 1
	d.reset()
	return message
}

func (d *Defragger) reset() {
	clear(d.frags)
	clear(d.small[:])
	d.frags = nil
	d.fragCount = 0
	d.count = 0
	d.size = 0
	if d.storage != nil {
		defragmentStoragePool.Put(d.storage)
		d.storage = nil
	}
	d.used = 0
}

func (d *Defragger) fragment(index uint8) []byte {
	if d.fragCount <= uint8(len(d.small)) {
		return d.small[index]
	}
	return d.frags[index]
}

func (d *Defragger) setFragment(index uint8, data []byte) {
	if d.fragCount <= uint8(len(d.small)) {
		d.small[index] = data
		return
	}
	d.frags[index] = data
}
