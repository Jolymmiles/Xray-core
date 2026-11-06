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
// Its sequence number is no evidence: BEP 29 initializes it to 1, but libutp
// and libtorrent start it at random.
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
	// above, and its question can end where a SYN's extensions would.
	if isDNSQuery(b) {
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

// SniffUTPDatagram is SniffUTP for a whole datagram: one too short for the
// header is no SYN, and no later datagram makes it one.
func SniffUTPDatagram(d []byte) (*SniffHeader, error) {
	if len(d) < 20 {
		return nil, errNotBittorrent
	}
	return SniffUTP(d)
}

// isDNSQuery reports whether b reads as a DNS query: query flags with no
// response code, and a first question whose name ends inside b and whose
// class is one a query asks for. A SYN reads its connection id as the flags
// and its receive window as the start of the question, which rarely fit both.
func isDNSQuery(b []byte) bool {
	if len(b) < 12 || b[2]&0x80 != 0 || b[3]&0x4F != 0 || binary.BigEndian.Uint16(b[4:6]) == 0 {
		return false
	}
	offset := 12
	for {
		if offset >= len(b) {
			return false
		}
		label := int(b[offset])
		if label == 0 {
			offset++
			break
		}
		if label > 63 || offset+1+label > 12+255 {
			return false
		}
		offset += 1 + label
	}
	if len(b) < offset+4 {
		return false
	}
	qtype, qclass := binary.BigEndian.Uint16(b[offset:offset+2]), binary.BigEndian.Uint16(b[offset+2:offset+4])
	// The root name is asked for its NS, SOA, DNSKEY or ANY in class IN.
	if offset == 13 {
		return qclass == 1 && (qtype == 2 || qtype == 6 || qtype == 48 || qtype == 255)
	}
	switch qclass {
	case 1, 3, 4, 254, 255: // IN, CH, HS, NONE, ANY
		return true
	}
	return false
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
