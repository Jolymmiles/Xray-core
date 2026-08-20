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

	// A DNS query whose transaction id starts with 0x01/0x11/0x21/0x31/0x41
	// and ends with 0x00 passes the checks above: the id reads as a valid
	// type/version pair, the flags 0x0100 read as a non-zero connection id,
	// and there is no extension chain to validate. DNS is orders of
	// magnitude more common than uTP on proxies, so pass over well-formed
	// queries explicitly.
	if isDNSQuery(b) {
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

// isDNSQuery reports whether b is shaped like a DNS query a real stub
// resolver or tool sends: a request (QR clear) with a deployed opcode
// (query, iquery, status, notify, update), one or two questions, and a
// first question whose labels are valid and whose type and class fit.
// Answer, authority and additional record counts are unconstrained, and
// trailing bytes are allowed: verified live against Cloudflare, Google,
// Quad9, OpenDNS, AdGuard, Yandex, AliDNS and DNSPod with plain, EDNS0,
// EDNS-cookie, padded, multi-record, two-question, trailing-garbage and
// dynamic-update shapes. A real uTP packet matching this would need its
// connection id to clear the response bit and opcode nibble and its
// timestamp to read as a question count of one or two.
func isDNSQuery(b []byte) bool {
	if len(b) < 17 { // header + one-label question + QTYPE + QCLASS
		return false
	}
	if b[2]&0x80 != 0 { // response, not a query from a client
		return false
	}
	if b[2]&0x78 > 0x28 { // opcode above the deployed set
		return false
	}
	switch binary.BigEndian.Uint16(b[4:6]) {
	case 1, 2:
	default:
		return false
	}

	pos := 12
	for {
		if pos >= len(b) {
			return false
		}
		length := int(b[pos])
		if length == 0 {
			pos++
			break
		}
		if length > 63 || pos+1+length > len(b) {
			return false
		}
		pos += 1 + length
	}
	return pos+4 <= len(b)
}
