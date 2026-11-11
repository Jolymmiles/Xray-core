package bittorrent

import (
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

	if b[0] == 19 && string(b[1:20]) == "BitTorrent protocol" {
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

	// Walk the extension chain: selective ack (1) and extension bits (2),
	// which µTorrent sends in its ST_SYN.
	extension, offset := b[1], 20
	for extension != 0 {
		if len(b) < offset+2 {
			return nil, errNotBittorrent
		}
		length := int(b[offset+1])
		switch extension {
		case 1:
			if length < 4 || length%4 != 0 {
				return nil, errNotBittorrent
			}
		case 2:
			if length != 8 {
				return nil, errNotBittorrent
			}
		default:
			return nil, errNotBittorrent
		}
		if len(b) < offset+2+length {
			return nil, errNotBittorrent
		}
		extension = b[offset]
		offset += 2 + length
	}

	// A SYN carries no data: its extensions end the datagram.
	if len(b) != offset {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
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
