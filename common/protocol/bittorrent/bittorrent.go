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
//	1        extension id (0 for a connection-opening SYN)
//	2-3      connection id
//	4-7      sender timestamp
//	8-11     timestamp difference (0 before the first response)
//	12-15    receive window
//	16-17    sequence number (1 for ST_SYN)
//	18-19    ack number
//
// The dispatcher sniffs the opening payload of a new UDP flow. Accepting
// established DATA, STATE, FIN or RESET headers here is unsafe because their
// unconstrained fields collide with ordinary game discovery and real-time
// media datagrams. A genuine new uTP flow starts with ST_SYN, whose fixed
// initial state provides enough evidence to classify it without probabilistic
// header matching.
func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if b[0] != 0x41 || b[1] != 0 {
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

	if binary.BigEndian.Uint16(b[16:18]) != 1 {
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
