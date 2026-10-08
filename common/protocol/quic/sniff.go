package quic

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	ptls "github.com/xtls/xray-core/common/protocol/tls"
	"golang.org/x/crypto/hkdf"
)

type SniffHeader struct {
	domain string
}

func (s SniffHeader) Protocol() string {
	return "quic"
}

func (s SniffHeader) Domain() string {
	return s.domain
}

var (
	errNotQUIC        = errors.New("not quic")
	errNotQUICInitial = errors.New("not initial packet")
	errNotClientHello = errors.New("the CRYPTO stream does not start with a ClientHello")
	errNoServerName   = errors.New("no server name in the ClientHello")

	errConflictingCrypto = errors.New("CRYPTO frames carry different data at the same offset")
)

// cryptoStreamCap bounds the CRYPTO stream offsets SniffQUIC keeps. A
// ClientHello is far smaller.
const cryptoStreamCap = 32768

// receivedBytes records which bytes of the CRYPTO stream have arrived.
type receivedBytes [cryptoStreamCap / 8]byte

// fill copies data, which starts at offset from of the stream, into stream
// and marks it received. A byte that has arrived before must arrive unchanged
// (RFC 9000, Section 2.2): receivers disagree on which copy of differing data
// counts, so fill reports false instead of choosing one.
func (r *receivedBytes) fill(stream, data []byte, from int32) bool {
	for i := int32(0); i < int32(len(data)); {
		at := from + i
		if at%8 == 0 && int32(len(data))-i >= 8 {
			// Eight bytes that all have or all have not arrived yet are
			// handled at once.
			switch r[at/8] {
			case 0x00:
				copy(stream[i:i+8], data[i:i+8])
				r[at/8] = 0xFF
				i += 8
				continue
			case 0xFF:
				if !bytes.Equal(stream[i:i+8], data[i:i+8]) {
					return false
				}
				i += 8
				continue
			}
		}
		if r[at/8]&(1<<(at%8)) == 0 {
			r[at/8] |= 1 << (at % 8)
			stream[i] = data[i]
		} else if stream[i] != data[i] {
			return false
		}
		i++
	}
	return true
}

// prefix returns the length of the start of the stream received without a
// gap, continuing from known, a length already received, up to end.
func (r *receivedBytes) prefix(known, end int32) int32 {
	for known < end && r[known/8]&(1<<(known%8)) != 0 {
		known++
	}
	return known
}

type quicVersionSpec struct {
	ver         uint32
	typeInitial byte
	typeRetry   byte
	initialSalt []byte
	labelPrefix string
}

var (
	quicDraft29 = quicVersionSpec{
		ver:         0xff00001d,
		typeInitial: 0b00,
		typeRetry:   0b11,
		initialSalt: []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		labelPrefix: "quic",
	}
	quicV1 = quicVersionSpec{
		ver:         0x1,
		typeInitial: 0b00,
		typeRetry:   0b11,
		initialSalt: []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		labelPrefix: "quic",
	}
	quicV2 = quicVersionSpec{
		ver:         0x6b3343cf,
		typeInitial: 0b01,
		typeRetry:   0b00,
		initialSalt: []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		labelPrefix: "quicv2",
	}

	quicVersionSpecMap = map[uint32]*quicVersionSpec{
		quicDraft29.ver: &quicDraft29,
		quicV1.ver:      &quicV1,
		quicV2.ver:      &quicV2,
	}
)

// SniffQUIC returns the server name in the ClientHello carried by the QUIC
// client Initial packets at the start of b.
//
// b holds the first datagrams of a UDP flow as the dispatcher caches them, and
// it is borrowed: the dispatcher forwards those datagrams once sniffing ends.
// SniffQUIC therefore never writes to b and removes the packet protection of
// each Initial packet in a copy.
func SniffQUIC(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	// Crypto data separated across packets. Frames arrive in any order and can
	// overlap or leave gaps (Chrome shuffles its ClientHello fragments, and
	// retransmissions split them differently), so the data is kept at its
	// stream offset and only the part received without a gap is read.
	cryptoLen := int32(0)
	cryptoDataBuf := buf.NewWithSize(cryptoStreamCap)
	defer cryptoDataBuf.Release()
	var received receivedBytes
	receivedLen := int32(0)
	// The packet whose protection is being removed, copied out of b.
	packetBuf := buf.NewWithSize(int32(len(b)))
	defer packetBuf.Release()

	// sniffed holds the Initial keys of the connection sniffed: the one of
	// the first Initial packet, which must decrypt or the flow is rejected. A
	// flow can carry Initial packets of other connections after it, which are
	// skipped.
	var sniffed *initialKeys

	// Parse QUIC packets
	for len(b) > 0 {
		hdr, err := parseLongHeader(b)
		if err != nil {
			if sniffed == nil {
				return nil, err
			}
			// What follows the last packet of a datagram is not a packet: Firefox
			// pads with zeros there. b keeps no datagram boundaries, so resume
			// at the next Initial packet of the connection.
			if b = sniffed.nextInitial(b); b == nil {
				break
			}
			continue
		}
		packet := b[:hdr.pnOffset+hdr.packetLen]
		b = b[len(packet):]
		if !hdr.initial || sniffed != nil && !sniffed.protects(hdr) { // Only Initial packets of the connection carry its ClientHello
			continue
		}

		keys := sniffed
		if keys == nil {
			keys = newInitialKeys(hdr.spec, hdr.destConnID)
		}
		decrypted, err := keys.open(packet, hdr.pnOffset, packetBuf)
		if err != nil {
			if sniffed == nil {
				return nil, err
			}
			continue
		}
		sniffed = keys

		buffer := buf.FromBytes(decrypted)
		for !buffer.IsEmpty() {
			frameType, _ := buffer.ReadByte()
			for frameType == 0x0 && !buffer.IsEmpty() {
				frameType, _ = buffer.ReadByte()
			}
			switch frameType {
			case 0x00: // PADDING frame
			case 0x01: // PING frame
			case 0x02, 0x03: // ACK frame
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Largest Acknowledged
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Delay
					return nil, io.ErrUnexpectedEOF
				}
				ackRangeCount, err := readShortQUICVarint(buffer) // Field: ACK Range Count
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: First ACK Range
					return nil, io.ErrUnexpectedEOF
				}
				for i := 0; i < int(ackRangeCount); i++ { // Field: ACK Range
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Range -> Gap
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Range -> ACK Range Length
						return nil, io.ErrUnexpectedEOF
					}
				}
				if frameType == 0x03 {
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ECN Counts -> ECT0 Count
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ECN Counts -> ECT1 Count
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
						return nil, io.ErrUnexpectedEOF
					}
				}
			case 0x06: // CRYPTO frame, we will use this frame
				offset, err := readShortQUICVarint(buffer) // Field: Offset
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				length, err := readShortQUICVarint(buffer) // Field: Length
				if err != nil || length > buffer.Len() {
					return nil, io.ErrUnexpectedEOF
				}
				currentCryptoLen := int32(offset + length)
				if cryptoLen < currentCryptoLen {
					if currentCryptoLen > cryptoStreamCap {
						return nil, io.ErrShortBuffer
					}
					cryptoDataBuf.Extend(currentCryptoLen - cryptoLen)
					cryptoLen = currentCryptoLen
				}
				data, err := buffer.ReadBytes(length) // Field: Crypto Data
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if !received.fill(cryptoDataBuf.BytesRange(offset, currentCryptoLen), data, offset) {
					// quic-go keeps a copy it has delivered, yet lets a longer
					// frame replace one still queued: no server name read here
					// is sure to be the one the destination reads.
					return nil, errConflictingCrypto
				}
			case 0x1c: // CONNECTION_CLOSE frame, only 0x1c is permitted in initial packet
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Error Code
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Frame Type
					return nil, io.ErrUnexpectedEOF
				}
				length, err := readShortQUICVarint(buffer) // Field: Reason Phrase Length
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err := buffer.ReadBytes(int32(length)); err != nil { // Field: Reason Phrase
					return nil, io.ErrUnexpectedEOF
				}
			default:
				// Only above frame types are permitted in initial packet.
				// See https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2-8
				return nil, errNotQUICInitial
			}
		}

		// The client's CRYPTO stream starts with its ClientHello: a handshake
		// header (type 1, 24-bit length) and the body. Read it only once all of
		// it has arrived; bytes still missing must never be read.
		receivedLen = received.prefix(receivedLen, cryptoLen)
		stream := cryptoDataBuf.BytesTo(receivedLen)
		if len(stream) < 4 {
			continue
		}
		if stream[0] != 1 {
			return nil, errNotClientHello
		}
		helloLen := 4 + (int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3]))
		if helloLen > cryptoStreamCap {
			return nil, errNotClientHello
		}
		if len(stream) < helloLen {
			continue
		}
		tlsHdr := &ptls.SniffHeader{}
		if err := ptls.ReadClientHello(stream[:helloLen], tlsHdr); err != nil {
			// The whole ClientHello has arrived, so later packets cannot help.
			return nil, errNoServerName
		}
		return &SniffHeader{domain: tlsHdr.Domain()}, nil
	}
	// All payload is parsed as valid QUIC packets, but we need more packets for crypto data to read client hello.
	return nil, protocol.ErrProtoNeedMoreData
}

// longHeader is the part of a QUIC long header packet the sniffer reads.
type longHeader struct {
	spec       *quicVersionSpec
	initial    bool
	destConnID []byte
	pnOffset   int // where the Packet Number field starts
	packetLen  int // the Packet Number field and the payload
}

// parseLongHeader parses the header of the long header packet at the start of
// b, which must hold the whole packet.
func parseLongHeader(b []byte) (longHeader, error) {
	buffer := buf.FromBytes(b)
	typeByte, err := buffer.ReadByte()
	if err != nil {
		return longHeader{}, errNotQUIC
	}

	isLongHeader := typeByte&0x80 > 0
	if !isLongHeader || typeByte&0x40 == 0 {
		return longHeader{}, errNotQUICInitial
	}

	vb, err := buffer.ReadBytes(4)
	if err != nil {
		return longHeader{}, errNotQUIC
	}

	s, ok := quicVersionSpecMap[binary.BigEndian.Uint32(vb)]
	if !ok {
		return longHeader{}, errNotQUIC
	}

	packetType := (typeByte & 0x30) >> 4
	if packetType == s.typeRetry {
		return longHeader{}, errNotQUICInitial
	}
	hdr := longHeader{spec: s, initial: packetType == s.typeInitial}

	if l, err := buffer.ReadByte(); err != nil {
		return longHeader{}, errNotQUIC
	} else if hdr.destConnID, err = buffer.ReadBytes(int32(l)); err != nil {
		return longHeader{}, errNotQUIC
	}

	if l, err := buffer.ReadByte(); err != nil {
		return longHeader{}, errNotQUIC
	} else if common.Error2(buffer.ReadBytes(int32(l))) != nil {
		return longHeader{}, errNotQUIC
	}

	if hdr.initial { // Only initial packets have token, see https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
		tokenLen, err := readShortQUICVarint(buffer)
		if err != nil || tokenLen > int32(len(b)) {
			return longHeader{}, errNotQUIC
		}

		if _, err = buffer.ReadBytes(tokenLen); err != nil {
			return longHeader{}, errNotQUIC
		}
	}

	packetLen, err := readShortQUICVarint(buffer)
	if err != nil {
		return longHeader{}, errNotQUIC
	}
	// packetLen is impossible to be shorter than this
	if packetLen < 4 {
		return longHeader{}, errNotQUIC
	}

	hdr.pnOffset = len(b) - int(buffer.Len())
	hdr.packetLen = int(packetLen)
	if len(b) < hdr.pnOffset+hdr.packetLen {
		return longHeader{}, common.ErrNoClue // Not enough data to read as a QUIC packet. QUIC is UDP-based, so this is unlikely to happen.
	}
	return hdr, nil
}

// initialKeys removes the protection of the client Initial packets of one
// connection (RFC 9001, Section 5).
type initialKeys struct {
	spec       *quicVersionSpec
	destConnID []byte
	hp         cipher.Block
	aead       cipher.AEAD
}

// newInitialKeys derives the client Initial keys that protect the packets of
// the connection with destination connection ID destConnID (RFC 9001, Section
// 5.2; RFC 9369, Section 3.3.1 for QUIC v2).
func newInitialKeys(s *quicVersionSpec, destConnID []byte) *initialKeys {
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, s.initialSalt)
	secret := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())
	// AES-128 accepts every 16-byte key.
	hp := common.Must2(aes.NewCipher(hkdfExpandLabel(secret, s.labelPrefix+" hp", 16)))
	key := hkdfExpandLabel(secret, s.labelPrefix+" key", 16)
	iv := hkdfExpandLabel(secret, s.labelPrefix+" iv", 12)
	return &initialKeys{spec: s, destConnID: destConnID, hp: hp, aead: AEADAESGCMTLS13(key, iv)}
}

// protects reports whether the packet with header hdr belongs to the
// connection.
func (k *initialKeys) protects(hdr longHeader) bool {
	return hdr.spec == k.spec && bytes.Equal(hdr.destConnID, k.destConnID)
}

// open returns the payload of an Initial packet of the connection whose Packet
// Number field starts at pnOffset. The packet is borrowed, so its protection
// is removed in a copy held by packetBuf.
func (k *initialKeys) open(packet []byte, pnOffset int, packetBuf *buf.Buffer) ([]byte, error) {
	// The header protection sample starts 4 bytes into the Packet Number field.
	if len(packet) < pnOffset+4+aes.BlockSize {
		return nil, errNotQUIC
	}
	var mask [aes.BlockSize]byte
	k.hp.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	packetBuf.Clear()
	unprotected := packetBuf.Extend(int32(len(packet)))
	copy(unprotected, packet)
	unprotected[0] ^= mask[0] & 0xf
	packetNumberLength := int(unprotected[0]&0x3 + 1)
	nonce := make([]byte, k.aead.NonceSize())
	for i := range packetNumberLength {
		unprotected[pnOffset+i] ^= mask[i+1]
	}
	copy(nonce[len(nonce)-packetNumberLength:], unprotected[pnOffset:pnOffset+packetNumberLength])

	extHdrLen := pnOffset + packetNumberLength
	return k.aead.Open(unprotected[extHdrLen:extHdrLen], nonce, unprotected[extHdrLen:], unprotected[:extHdrLen])
}

// nextInitial returns b from the next Initial packet of the connection after
// the first byte of b, or nil if there is none.
func (k *initialKeys) nextInitial(b []byte) []byte {
	// A long header packet starts with its type byte, the version and the
	// length-prefixed Destination Connection ID.
	var signature [4 + 1 + 255]byte
	binary.BigEndian.PutUint32(signature[:4], k.spec.ver)
	signature[4] = byte(len(k.destConnID))
	n := 5 + copy(signature[5:], k.destConnID)
	for start := 1; start < len(b); start++ {
		index := bytes.Index(b[start+1:], signature[:n])
		if index < 0 {
			return nil
		}
		start += index
		if typeByte := b[start]; typeByte&0xc0 == 0xc0 && (typeByte&0x30)>>4 == k.spec.typeInitial {
			return b[start:]
		}
	}
	return nil
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	b := make([]byte, 0, 2+1+6+len(label)+1)
	b = binary.BigEndian.AppendUint16(b, uint16(length))
	b = append(b, byte(6+len(label)))
	b = append(b, "tls13 "...)
	b = append(b, label...)
	b = append(b, 0) // context

	out := make([]byte, length)
	n, err := hkdf.Expand(crypto.SHA256.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// readShortQUICVarint wraps quicvarint.Read with a max limit for length related fields.
// we only handle QUIC Initial so these numbers should not exceed 65535
// returns int32 to reduce type conversion
func readShortQUICVarint(reader io.ByteReader) (int32, error) {
	v, err := quicvarint.Read(reader)
	if err != nil {
		return 0, err
	}
	if v > 65535 {
		// not used(
		return 0, errNotQUICInitial
	}
	return int32(v), nil
}
