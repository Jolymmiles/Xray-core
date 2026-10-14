package quic

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"math/bits"

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

	// The Initial packets servers do not read alike, or not at all.
	errShortInitialDatagram = errors.New("an Initial packet in a datagram below 1200 bytes")
	errInitialNotFirst      = errors.New("the first Initial packet of the flow is not the first packet of its datagram")
	errShortDestConnID      = errors.New("the first Initial packet of the flow has a Destination Connection ID below 8 bytes")
	errReservedBits         = errors.New("an Initial packet with its reserved bits set")
	errOtherSourceConnID    = errors.New("an Initial packet of the connection with another Source Connection ID")
	errServersPartWays      = errors.New("an Initial packet of the connection after a packet some servers stop reading its datagram at")
)

const (
	// minInitialDatagram is the smallest datagram a server takes an Initial
	// packet in (RFC 9000, Section 14.1).
	minInitialDatagram = 1200
	// minFirstDestConnID is the shortest Destination Connection ID a client
	// puts in its first Initial packet (RFC 9000, Section 7.2).
	minFirstDestConnID = 8
	// maxConnID is the longest connection ID of a long header packet of the
	// versions sniffed (RFC 9000, Section 17.2).
	maxConnID = 20
)

// cryptoStreamCap bounds the CRYPTO stream offsets SniffQUIC keeps. The
// stream starts with the ClientHello, which the TLS sniffer bounds the same.
const cryptoStreamCap = ptls.MaxClientHelloLength

// receivedBytes records which bytes of the CRYPTO stream have arrived: bit
// at%8 of byte at/8 is set once the byte at offset at has.
type receivedBytes [cryptoStreamCap / 8]byte

// fill copies data, which starts at offset from of the stream, into stream
// and marks it received. A byte that has arrived before must arrive unchanged
// (RFC 9000, Section 2.2): receivers disagree on which copy of differing data
// counts, so fill reports false instead of choosing one.
func (r *receivedBytes) fill(stream, data []byte, from int32) bool {
	end := from + int32(len(data))
	for at := from; at < end; {
		i := at - from
		// A whole bitmap byte that is clear or set starts a run of at least
		// eight bytes that have or have not arrived: find where it ends 64
		// bits at a time, and compare or copy it at once.
		if at%8 == 0 && end-at >= 8 {
			switch r[at/8] {
			case 0x00:
				to := r.runEnd(at, end, false)
				copy(stream[i:to-from], data[i:to-from])
				r.mark(at, to)
				at = to
				continue
			case 0xFF:
				to := r.runEnd(at, end, true)
				if !bytes.Equal(stream[i:to-from], data[i:to-from]) {
					return false
				}
				at = to
				continue
			}
		}
		// Elsewhere, in short frames and runs, one byte at a time costs less
		// than finding where its run ends.
		bit := byte(1) << (at % 8)
		if r[at/8]&bit == 0 {
			r[at/8] |= bit
			stream[i] = data[i]
		} else if stream[i] != data[i] {
			return false
		}
		at++
	}
	return true
}

// runEnd returns where the run of bytes starting at offset at ends, up to
// end: the run of bytes that have arrived if received is true, or of bytes
// that have not if it is false. It reads the bitmap 64 bits at a time.
func (r *receivedBytes) runEnd(at, end int32, received bool) int32 {
	var flip uint64
	if received {
		flip = ^uint64(0)
	}
	for at < end {
		word := at / 64
		// The bits of the bytes that end the run are set.
		w := (binary.LittleEndian.Uint64(r[word*8:]) ^ flip) >> (at % 64)
		if w != 0 {
			return min(at+int32(bits.TrailingZeros64(w)), end)
		}
		at = (word + 1) * 64
	}
	return end
}

// mark records the bytes from offset from up to offset to as received.
func (r *receivedBytes) mark(from, to int32) {
	for ; from < to && from%8 != 0; from++ {
		r[from/8] |= 1 << (from % 8)
	}
	for ; to-from >= 8; from += 8 {
		r[from/8] = 0xFF
	}
	for ; from < to; from++ {
		r[from/8] |= 1 << (from % 8)
	}
}

// prefix returns the length of the start of the stream received without a
// gap, continuing from known, a length already received, up to end.
func (r *receivedBytes) prefix(known, end int32) int32 {
	return r.runEnd(known, end, true)
}

type quicVersionSpec struct {
	ver         uint32
	typeInitial byte
	typeZeroRTT byte
	typeRetry   byte
	initialSalt []byte
	labelPrefix string
}

var (
	quicDraft29 = quicVersionSpec{
		ver:         0xff00001d,
		typeInitial: 0b00,
		typeZeroRTT: 0b01,
		typeRetry:   0b11,
		initialSalt: []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		labelPrefix: "quic",
	}
	quicV1 = quicVersionSpec{
		ver:         0x1,
		typeInitial: 0b00,
		typeZeroRTT: 0b01,
		typeRetry:   0b11,
		initialSalt: []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		labelPrefix: "quic",
	}
	quicV2 = quicVersionSpec{
		ver:         0x6b3343cf,
		typeInitial: 0b01,
		typeZeroRTT: 0b10,
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
// b holds the first datagrams of a UDP flow without their boundaries, and it
// is borrowed: the dispatcher forwards those datagrams once sniffing ends.
// SniffQUIC therefore never writes to b and removes the packet protection of
// each Initial packet in a copy.
//
// It reads the header of each Initial packet as servers do, and names no
// server where none reads the packet or where they part ways:
//
//   - A packet with a connection ID longer than 20 bytes does not parse (RFC
//     9000, Section 17.2).
//   - An Initial packet with its reserved bits set, once its protection is
//     removed, closes the connection (RFC 9000, Section 17.2).
//   - A client sends a Destination Connection ID of at least 8 bytes in its
//     first Initial packet (RFC 9000, Section 7.2). quic-go drops a first
//     Initial packet with a shorter one, x/net/quic reads it.
//   - RFC 9000, Section 7.2 has a server discard a later Initial packet of
//     the connection with another Source Connection ID: quic-go does,
//     x/net/quic does not.
func SniffQUIC(b []byte) (*SniffHeader, error) {
	return sniffQUIC([][]byte{b}, false)
}

// SniffQUICDatagrams is SniffQUIC for the first datagrams of a UDP flow kept
// apart, as the dispatcher forwards them. It reads each datagram as a QUIC
// server receives one, and names no server where servers part ways:
//
//   - A packet never continues into the next datagram, and a datagram is read
//     up to its first packet that does not parse. Before the connection has
//     started, a datagram whose first packet does not parse, or runs past
//     the end of the datagram, ends sniffing without a server name, though a
//     server goes on to later datagrams.
//   - The first Initial packet of the flow starts the connection only in a
//     datagram of at least 1200 bytes (RFC 9000, Section 14.1), and only as
//     the first packet of the datagram, as quic-go and x/net/quic check;
//     quiche does not check the size. A datagram with an Initial packet that
//     cannot start the connection ends sniffing at once: no valid client
//     sends one, and the sniffer neither names the server of a packet that
//     servers ignore nor holds the flow for a datagram that may never come.
//   - Once the connection has started, a new Initial packet of it in a
//     datagram below 1200 bytes ends sniffing: quic-go reads it, x/net/quic
//     and nginx drop it.
//   - Servers part ways on the packets of a datagram after a packet of
//     another connection or version (quic-go stops reading the datagram;
//     lsquic, picoquic and quicly read on), after a packet of the connection
//     that does not decrypt (x/net/quic, quiche and ngtcp2 stop; quic-go and
//     picoquic read on), after a repeated one (quiche, ngtcp2 and picoquic
//     stop; quic-go and x/net/quic read on), and after a 0-RTT packet
//     (x/net/quic stops, quic-go reads on). A new Initial packet of the
//     connection after such a packet ends sniffing. Valid clients coalesce
//     packets of one connection and version, in the order of their encryption
//     levels (RFC 9000, Section 12.2), and never repeat a packet number.
//
// Where servers part ways with no packet to tell by, the sniffer reads the
// flow whole: a long datagram, of which quic-go reads the first 1452 bytes and
// x/net/quic the first 1472, and a connection of QUIC v2 or draft-29, which a
// server that does not support its version ignores, reading a later
// connection of the flow instead.
//
// The datagrams are borrowed like the payload of SniffQUIC.
func SniffQUICDatagrams(datagrams [][]byte) (*SniffHeader, error) {
	return sniffQUIC(datagrams, true)
}

// sniffQUIC implements SniffQUIC and SniffQUICDatagrams. Unless separate is
// set, datagrams holds one byte stream whose datagram boundaries are unknown.
func sniffQUIC(datagrams [][]byte, separate bool) (*SniffHeader, error) {
	largest := 0
	for _, datagram := range datagrams {
		largest = max(largest, len(datagram))
	}
	if largest == 0 {
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
	// The packet whose protection is being removed, copied out of its
	// datagram.
	packetBuf := buf.NewWithSize(int32(largest))
	defer packetBuf.Release()

	// sniffed holds the Initial keys of the connection sniffed: the one of
	// the first Initial packet, which must decrypt or the flow is rejected. A
	// flow can carry Initial packets of other connections after it, which are
	// skipped.
	var sniffed *initialKeys

	for _, b := range datagrams {
		datagramLen := len(b)
		// The connection and version of the first packet of the datagram.
		var datagramConnID []byte
		var datagramSpec *quicVersionSpec
		// partWays is set once the datagram holds a packet that some servers
		// stop reading it at and others read past.
		partWays := false
	packets:
		for len(b) > 0 {
			first := len(b) == datagramLen
			hdr, err := parseLongHeader(b)
			if err != nil {
				if sniffed == nil && (!separate || first) {
					return nil, err
				}
				if separate {
					break packets
				}
				// What follows the last packet of a datagram is not a packet:
				// Firefox pads with zeros there. b keeps no datagram boundaries,
				// so resume at the next Initial packet of the connection.
				if b = sniffed.nextInitial(b); b == nil {
					break packets
				}
				continue
			}
			packet := b[:hdr.pnOffset+hdr.packetLen]
			b = b[len(packet):]
			if separate {
				if sniffed == nil && hdr.initial {
					// The datagram of the first Initial packet must be able
					// to start the connection.
					if datagramLen < minInitialDatagram {
						return nil, errShortInitialDatagram
					}
					if !first {
						return nil, errInitialNotFirst
					}
				}
				if first {
					datagramConnID, datagramSpec = hdr.destConnID, hdr.spec
				} else if hdr.spec != datagramSpec || !bytes.Equal(hdr.destConnID, datagramConnID) {
					// A server gives a datagram to the connection of its first
					// packet and drops this one; quic-go drops what follows.
					partWays = true
					continue
				}
				if hdr.zeroRTT(packet) {
					// x/net/quic drops what follows a 0-RTT packet.
					partWays = true
					continue
				}
			}
			if !hdr.initial || sniffed != nil && !sniffed.protects(hdr) { // Only Initial packets of the connection carry its ClientHello
				continue
			}

			keys := sniffed
			if keys == nil {
				if len(hdr.destConnID) < minFirstDestConnID {
					return nil, errShortDestConnID
				}
				keys = newInitialKeys(hdr.spec, hdr.destConnID)
				keys.srcConnID = hdr.srcConnID(packet)
			}
			decrypted, pn, err := keys.open(packet, hdr.pnOffset, packetBuf)
			if err != nil {
				if sniffed == nil || err == errReservedBits {
					return nil, err
				}
				// x/net/quic, quiche and ngtcp2 drop what follows.
				partWays = true
				continue
			}
			if !keys.firstOpen(pn) {
				// A server discards the copy: only the first one counts.
				// quiche, ngtcp2 and picoquic drop what follows.
				partWays = true
				continue
			}
			if sniffed != nil {
				switch {
				case separate && datagramLen < minInitialDatagram:
					return nil, errShortInitialDatagram
				case separate && partWays:
					return nil, errServersPartWays
				case !bytes.Equal(hdr.srcConnID(packet), sniffed.srcConnID):
					return nil, errOtherSourceConnID
				}
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
			helloLen, ok := ptls.HandshakeMessageLength(stream)
			if !ok {
				continue
			}
			if stream[0] != 1 || helloLen > cryptoStreamCap {
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
	}
	// All payload is parsed as valid QUIC packets, but we need more packets for crypto data to read client hello.
	return nil, protocol.ErrProtoNeedMoreData
}

// longHeader is the part of a QUIC long header packet the sniffer reads.
// parseLongHeader returns it and an error in the 9 registers the Go ABI has
// for results; one more field would send them through memory for every
// packet. What the sniffer reads of some packets only, the methods below read
// from the packet.
type longHeader struct {
	spec       *quicVersionSpec
	initial    bool
	destConnID []byte
	pnOffset   int // where the Packet Number field starts
	packetLen  int // the Packet Number field and the payload
}

// zeroRTT reports whether packet, whose header is hdr, is a 0-RTT packet.
func (hdr longHeader) zeroRTT(packet []byte) bool {
	return (packet[0]&0x30)>>4 == hdr.spec.typeZeroRTT
}

// srcConnID returns the Source Connection ID of packet, whose header is hdr.
func (hdr longHeader) srcConnID(packet []byte) []byte {
	// The type byte, the version, then the length-prefixed connection IDs.
	at := 1 + 4 + 1 + len(hdr.destConnID)
	return packet[at+1 : at+1+int(packet[at])]
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

	if l, err := buffer.ReadByte(); err != nil || l > maxConnID {
		return longHeader{}, errNotQUIC
	} else if hdr.destConnID, err = buffer.ReadBytes(int32(l)); err != nil {
		return longHeader{}, errNotQUIC
	}

	if l, err := buffer.ReadByte(); err != nil || l > maxConnID {
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
	// srcConnID is the Source Connection ID of the first Initial packet.
	srcConnID []byte
	hp        cipher.Block
	aead      cipher.AEAD
	// largest is the largest packet number opened so far, -1 before any.
	largest int64
	// opened records the packet numbers opened so far: below 1024 in
	// openedLow, others in openedHigh.
	openedLow  [1024 / 64]uint64
	openedHigh map[uint64]struct{}
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
	return &initialKeys{spec: s, destConnID: destConnID, hp: hp, aead: AEADAESGCMTLS13(key, iv), largest: -1}
}

// protects reports whether the packet with header hdr belongs to the
// connection.
func (k *initialKeys) protects(hdr longHeader) bool {
	return hdr.spec == k.spec && bytes.Equal(hdr.destConnID, k.destConnID)
}

// open returns the payload and the packet number of an Initial packet of the
// connection whose Packet Number field starts at pnOffset. The packet number
// is recovered from the largest one opened so far, as a receiver does (RFC
// 9000, Appendix A). The packet is borrowed, so its protection is removed in a
// copy held by packetBuf. A packet that decrypts with its reserved bits set
// yields errReservedBits.
func (k *initialKeys) open(packet []byte, pnOffset int, packetBuf *buf.Buffer) ([]byte, uint64, error) {
	// The header protection sample starts 4 bytes into the Packet Number field.
	if len(packet) < pnOffset+4+aes.BlockSize {
		return nil, 0, errNotQUIC
	}
	var mask [aes.BlockSize]byte
	k.hp.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	packetBuf.Clear()
	unprotected := packetBuf.Extend(int32(len(packet)))
	copy(unprotected, packet)
	unprotected[0] ^= mask[0] & 0xf
	packetNumberLength := int(unprotected[0]&0x3 + 1)
	var truncated uint64
	for i := range packetNumberLength {
		unprotected[pnOffset+i] ^= mask[i+1]
		truncated = truncated<<8 | uint64(unprotected[pnOffset+i])
	}
	pn := decodePacketNumber(k.largest, truncated, packetNumberLength)
	nonce := make([]byte, k.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], pn)

	extHdrLen := pnOffset + packetNumberLength
	payload, err := k.aead.Open(unprotected[extHdrLen:extHdrLen], nonce, unprotected[extHdrLen:], unprotected[:extHdrLen])
	if err == nil && unprotected[0]&0x0c != 0 {
		// The reserved bits are checked once both protections are removed
		// (RFC 9000, Section 17.2).
		return nil, pn, errReservedBits
	}
	return payload, pn, err
}

// firstOpen reports whether packet number pn is opened for the first time,
// and records it as opened. A receiver discards a packet whose number it has
// opened before (RFC 9000, Section 12.3).
func (k *initialKeys) firstOpen(pn uint64) bool {
	if pn < uint64(len(k.openedLow))*64 {
		bit := uint64(1) << (pn % 64)
		if k.openedLow[pn/64]&bit != 0 {
			return false
		}
		k.openedLow[pn/64] |= bit
	} else {
		if _, ok := k.openedHigh[pn]; ok {
			return false
		}
		if k.openedHigh == nil {
			k.openedHigh = make(map[uint64]struct{})
		}
		k.openedHigh[pn] = struct{}{}
	}
	k.largest = max(k.largest, int64(pn))
	return true
}

// decodePacketNumber recovers a packet number sent as its pnLen least
// significant bytes, truncated, from largest, the largest packet number
// received so far or -1 (RFC 9000, Appendix A.3).
func decodePacketNumber(largest int64, truncated uint64, pnLen int) uint64 {
	expected := uint64(largest + 1)
	window := uint64(1) << (8 * pnLen)
	halfWindow := window / 2
	candidate := expected&^(window-1) | truncated
	switch {
	case candidate+halfWindow <= expected && candidate < 1<<62-window:
		return candidate + window
	case candidate > expected+halfWindow && candidate >= window:
		return candidate - window
	}
	return candidate
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
