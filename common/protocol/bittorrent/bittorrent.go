package bittorrent

import (
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

// The uTP header layout per BEP 29:
//
//	0        type (4 bits, ST_DATA..ST_RESET) and version (4 bits, always 1)
//	1        extension id of the first extension header, 0 when there is none
//	2-3      connection id
//	4-19     timestamps, window size, sequence number, ack number
//	20+      extension headers: next id (1 byte), length (1 byte), data
//
// Deployed stacks send no extension (id 0), the selective-ack extension
// (id 1, both libutp and libtorrent), or libtorrent's close reason
// (id 3, utp_close_reason). libutp's parser also knows an extension-bits
// id 2, but no maintained stack sends it, so 2 and anything above 3 mean
// the payload is not uTP. The timestamp fields carry monotonic clock
// microseconds (libutp: CLOCK_MONOTONIC, libtorrent: steady_clock or
// system_clock depending on the standard library, truncated to 32 bits),
// not a common Unix-epoch base, so they cannot be validated against the
// local clock and are not checked.
func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if b[0]>>4 > 4 || b[0]&0xF != 1 {
		return nil, errNotBittorrent
	}

	extension := b[1]
	if extension != 0 && extension != 1 && extension != 3 {
		return nil, errNotBittorrent
	}

	// Deployed stacks never emit version-1 uTP with no extension and a
	// zero connection id: connection ids are random and echoed for the
	// whole session. A WireGuard handshake initiation starts with exactly
	// 0x01 0x00 0x00 0x00 (type, reserved), and its key material would
	// otherwise pass every structural check, so reject the shape here.
	if extension == 0 && b[2] == 0 && b[3] == 0 {
		return nil, errNotBittorrent
	}

	// Extension headers follow the fixed 20-byte header: each one is the
	// next extension id, the data length, then that many bytes of data.
	for offset := 20; extension != 0; {
		if extension != 1 && extension != 3 {
			return nil, errNotBittorrent
		}
		if offset+2 > len(b) {
			return nil, common.ErrNoClue
		}
		next := b[offset]
		offset += 2 + int(b[offset+1])
		if offset > len(b) {
			return nil, common.ErrNoClue
		}
		extension = next
	}

	return &SniffHeader{}, nil
}
