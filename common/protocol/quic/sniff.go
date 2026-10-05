package quic

import (
	"crypto"
	"crypto/aes"
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
)

// cryptoStreamCap bounds the CRYPTO stream offsets SniffQUIC keeps. A
// ClientHello is far smaller.
const cryptoStreamCap = 32768

// receivedBytes records which bytes of the CRYPTO stream have arrived.
type receivedBytes [cryptoStreamCap / 8]byte

func (r *receivedBytes) mark(from, to int32) {
	for i := from; i < to; i++ {
		r[i/8] |= 1 << (i % 8)
	}
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
	cache := buf.New()
	defer cache.Release()
	// The packet whose protection is being removed, copied out of b.
	packetBuf := buf.NewWithSize(int32(len(b)))
	defer packetBuf.Release()

	// Parse QUIC packets
	for len(b) > 0 {
		buffer := buf.FromBytes(b)
		typeByte, err := buffer.ReadByte()
		if err != nil {
			return nil, errNotQUIC
		}

		isLongHeader := typeByte&0x80 > 0
		if !isLongHeader || typeByte&0x40 == 0 {
			return nil, errNotQUICInitial
		}

		vb, err := buffer.ReadBytes(4)
		if err != nil {
			return nil, errNotQUIC
		}

		versionNumber := binary.BigEndian.Uint32(vb)
		var s *quicVersionSpec
		if v, ok := quicVersionSpecMap[versionNumber]; ok {
			s = v
		} else {
			return nil, errNotQUIC
		}

		packetType := (typeByte & 0x30) >> 4
		if packetType == s.typeRetry {
			return nil, errNotQUICInitial
		}

		var destConnID []byte
		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQUIC
		} else if destConnID, err = buffer.ReadBytes(int32(l)); err != nil {
			return nil, errNotQUIC
		}

		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQUIC
		} else if common.Error2(buffer.ReadBytes(int32(l))) != nil {
			return nil, errNotQUIC
		}

		isQUICInitial := packetType == s.typeInitial

		if isQUICInitial { // Only initial packets have token, see https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
			tokenLen, err := readShortQUICVarint(buffer)
			if err != nil || tokenLen > int32(len(b)) {
				return nil, errNotQUIC
			}

			if _, err = buffer.ReadBytes(tokenLen); err != nil {
				return nil, errNotQUIC
			}
		}

		packetLen, err := readShortQUICVarint(buffer)
		if err != nil {
			return nil, errNotQUIC
		}
		// packetLen is impossible to be shorter than this
		if packetLen < 4 {
			return nil, errNotQUIC
		}

		hdrLen := len(b) - int(buffer.Len())
		if len(b) < hdrLen+int(packetLen) {
			return nil, common.ErrNoClue // Not enough data to read as a QUIC packet. QUIC is UDP-based, so this is unlikely to happen.
		}

		restPayload := b[hdrLen+int(packetLen):]
		// cachedReader can concatenate zero-padded UDP datagrams.
		for len(restPayload) > 0 && restPayload[0] == 0 {
			restPayload = restPayload[1:]
		}
		if !isQUICInitial { // Skip this packet if it's not initial packet
			b = restPayload
			continue
		}

		salt := s.initialSalt
		label := s.labelPrefix
		initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
		secret := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())
		hpKey := hkdfExpandLabel(secret, label+" hp", 16)
		block, err := aes.NewCipher(hpKey)
		if err != nil {
			return nil, err
		}
		if len(b) < hdrLen+4+block.BlockSize() {
			return nil, errNotQUIC
		}
		cache.Clear()
		mask := cache.Extend(int32(block.BlockSize()))
		block.Encrypt(mask, b[hdrLen+4:hdrLen+4+len(mask)])
		packetBuf.Clear()
		packet := packetBuf.Extend(int32(hdrLen) + packetLen)
		copy(packet, b)
		packet[0] ^= mask[0] & 0xf
		packetNumberLength := int(packet[0]&0x3 + 1)
		for i := range packetNumberLength {
			packet[hdrLen+i] ^= mask[i+1]
		}

		key := hkdfExpandLabel(secret, label+" key", 16)
		iv := hkdfExpandLabel(secret, label+" iv", 12)
		cipher := AEADAESGCMTLS13(key, iv)

		nonce := cache.Extend(int32(cipher.NonceSize()))
		copy(nonce[len(nonce)-packetNumberLength:], packet[hdrLen:hdrLen+packetNumberLength])

		extHdrLen := hdrLen + packetNumberLength
		decrypted, err := cipher.Open(packet[extHdrLen:extHdrLen], nonce, packet[extHdrLen:], packet[:extHdrLen])
		if err != nil {
			return nil, err
		}
		buffer = buf.FromBytes(decrypted)
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
				if _, err := buffer.Read(cryptoDataBuf.BytesRange(offset, currentCryptoLen)); err != nil { // Field: Crypto Data
					return nil, io.ErrUnexpectedEOF
				}
				received.mark(offset, currentCryptoLen)
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
			b = restPayload
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
			b = restPayload
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
