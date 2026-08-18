package bittorrent

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common"
)

// SniffUDPTracker detects UDP tracker requests (BEP 15). A fresh tracker
// flow starts with the 16-byte connect request carrying the fixed protocol
// id 0x41727101980 and action 0. A client reusing a cached connection id
// may instead open a flow with an announce (action 1, exactly 98 bytes,
// event 0..3, nonzero listen port) or a scrape (action 2, 16 + 4N bytes).
func SniffUDPTracker(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	if len(b) == 16 && binary.BigEndian.Uint64(b[:8]) == 0x41727101980 && binary.BigEndian.Uint32(b[8:12]) == 0 {
		return &SniffHeader{}, nil
	}

	if len(b) == 98 && binary.BigEndian.Uint32(b[8:12]) == 1 {
		event := binary.BigEndian.Uint32(b[80:84])
		port := binary.BigEndian.Uint16(b[96:98])
		if event <= 3 && port != 0 {
			return &SniffHeader{}, nil
		}
	}

	if len(b) >= 20 && len(b)%4 == 0 && binary.BigEndian.Uint32(b[8:12]) == 2 {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}
