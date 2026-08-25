package bittorrent

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common"
)

// SniffUDPTracker detects UDP tracker connect requests (BEP 15): at least
// 16 bytes carrying the fixed protocol id 0x41727101980 and action 0.
//
// Announce (action 1) and scrape (action 2) requests reusing a cached
// connection id are deliberately not classified. They carry no protocol id,
// so the only observable anchors are small counter values at offset 8 —
// a shape ordinary game and real-time media datagrams reproduce constantly.
// Classifying them produced false bittorrent verdicts on legitimate UDP
// flows; a client whose cached connection id expires re-sends connect,
// which this sniffer does catch.
func SniffUDPTracker(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	if len(b) >= 16 && binary.BigEndian.Uint64(b[:8]) == 0x41727101980 && binary.BigEndian.Uint32(b[8:12]) == 0 {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}
