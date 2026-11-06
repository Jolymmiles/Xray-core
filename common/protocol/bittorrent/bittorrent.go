package bittorrent

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/xtls/xray-core/common"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBittorrent = errors.New("not bittorrent header")

func SniffBittorrent(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if bytes.HasPrefix(b, btHandshake) {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

// The uTP ST_SYN header layout per BEP 29:
//
//	0        type (4 bits, ST_SYN=4) and version (4 bits, always 1)
//	1        first extension id
//	2-3      connection id
//	4-7      sender timestamp
//	8-11     timestamp difference (0 before the first response)
//	12-15    receive window
//	16-17    sequence number
//	18-19    ack number
//
// The dispatcher sniffs the opening payload of a new UDP flow. Accepting
// established DATA, STATE, FIN or RESET headers here is unsafe because their
// unconstrained fields collide with ordinary game discovery and real-time
// media datagrams. A genuine new uTP flow starts with ST_SYN: no timestamp
// difference yet, and extensions, if any, that end where the datagram does.
// Its sequence number is no evidence: libutp and libtorrent start it at
// random, as BEP 29 leaves them free to.
func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if b[0] == 0x01 {
		return sniffUTPHandshake(b)
	}
	if b[0] != 0x41 {
		return nil, errNotBittorrent
	}

	// TURN ChannelData channel 0x4100 shares the same leading bytes as a
	// version-1 uTP ST_SYN. Prefer a complete TURN frame over interpreting its
	// length and payload bytes as uTP connection state.
	if isTURNChannelData(b) {
		return nil, errNotBittorrent
	}

	if b[2] == 0 && b[3] == 0 {
		return nil, errNotBittorrent
	}

	if binary.BigEndian.Uint32(b[8:12]) != 0 {
		return nil, errNotBittorrent
	}

	// A DNS query with transaction id 0x41xx and no EDNS shares the fields
	// above, and its question can end where a SYN's extensions would. Its
	// QDCOUNT and ANCOUNT are where a SYN carries its timestamp: one or two
	// questions and at most one answer is a DNS header, and a timestamp of
	// that shape one in a billion.
	if qd, an := binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8]); qd >= 1 && qd <= 2 && an <= 1 {
		return nil, errNotBittorrent
	}

	// A SYN carries no data: its extensions end the datagram.
	if offset, ok := utpExtensionsEnd(b); !ok || offset != len(b) {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

// utpExtensionsEnd walks the extension chain after the 20-byte header:
// selective ack (1) and extension bits (2), which µTorrent sends in its
// ST_SYN. It returns where the chain ends.
func utpExtensionsEnd(b []byte) (int, bool) {
	extension, offset := b[1], 20
	for extension != 0 {
		if len(b) < offset+2 {
			return 0, false
		}
		length := int(b[offset+1])
		switch extension {
		case 1:
			if length < 4 || length%4 != 0 {
				return 0, false
			}
		case 2:
			if length != 8 {
				return 0, false
			}
		default:
			return 0, false
		}
		if len(b) < offset+2+length {
			return 0, false
		}
		extension = b[offset]
		offset += 2 + length
	}
	return offset, true
}

// btHandshake opens the peer protocol of BEP 3, over TCP and in uTP alike.
var btHandshake = []byte("\x13BitTorrent protocol")

// sniffUTPHandshake takes a uTP ST_DATA (type 0, version 1) whose data
// opens with the BitTorrent handshake: the first data of a uTP flow, as a
// flow sniffed after its SYN carries it.
func sniffUTPHandshake(b []byte) (*SniffHeader, error) {
	offset, ok := utpExtensionsEnd(b)
	if !ok || !bytes.HasPrefix(b[offset:], btHandshake) {
		return nil, errNotBittorrent
	}
	return &SniffHeader{}, nil
}

// SniffHTTPTracker takes an HTTP tracker request (BEP 3): a GET whose
// request line carries info_hash= with peer_id= (an announce) or /scrape?.
// It runs before the HTTP sniffer, which would otherwise take the flow as
// HTTP.
func SniffHTTPTracker(b []byte) (*SniffHeader, error) {
	const get = "GET /"
	if len(b) < len(get) {
		if bytes.HasPrefix([]byte(get), b) {
			return nil, common.ErrNoClue
		}
		return nil, errNotBittorrent
	}
	if !bytes.HasPrefix(b, []byte(get)) {
		return nil, errNotBittorrent
	}
	line := b
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		line = b[:i]
	}
	if bytes.Contains(line, []byte("info_hash=")) && (bytes.Contains(line, []byte("peer_id=")) || bytes.Contains(line, []byte("/scrape?"))) {
		return &SniffHeader{}, nil
	}
	return nil, errNotBittorrent
}

// SniffLSD takes BitTorrent local service discovery (BEP 14), which a TUN
// client may send into the tunnel with the rest of its multicast.
func SniffLSD(b []byte) (*SniffHeader, error) {
	const search = "BT-SEARCH * HTTP/1.1\r\n"
	if len(b) < len(search) {
		return nil, common.ErrNoClue
	}
	if !bytes.HasPrefix(b, []byte(search)) {
		return nil, errNotBittorrent
	}
	return &SniffHeader{}, nil
}

func isTURNChannelData(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	channel := binary.BigEndian.Uint16(b[:2])
	if channel < 0x4000 || channel > 0x7FFF {
		return false
	}
	return int(binary.BigEndian.Uint16(b[2:4])) == len(b)-4
}
