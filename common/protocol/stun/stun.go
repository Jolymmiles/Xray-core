// Package stun sniffs STUN (RFC 8489, RFC 5389) and the TURN messages that
// share its header (RFC 8656): the binding requests of ICE in WebRTC and of
// the calls in WhatsApp, Telegram and FaceTime, and their relay allocations.
// In ICE the media follows the STUN checks on the same pair of ports, so a
// rule on the first datagram routes the flow those checks open: on a UDP
// association, as with every first-datagram rule, whatever else the client
// sends on that socket takes the same route.
package stun

import (
	"encoding/binary"
	"errors"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "stun"
}

func (h *SniffHeader) Domain() string {
	return ""
}

// The STUN header per RFC 8489, section 5:
//
//	0-1      type: two zero bits, then 14 bits of method and class
//	2-3      length of the attributes that follow, a multiple of 4
//	4-7      magic cookie 0x2112A442
//	8-19     transaction id
//
// Each attribute is a 2-byte type and a 2-byte length, its value padded to a
// multiple of 4.
const (
	headerLen   = 20
	magicCookie = 0x2112A442
)

// MaxMessageLen is the most of a stream the dispatcher shows a sniffer
// (app/dispatcher's cache). A longer message is turned down: waiting for it
// would keep the server reading, and caching, what the client sends for the
// whole sniff budget, and the message would never be shown whole.
const MaxMessageLen = 32768

var errNotSTUN = errors.New("not stun")

// SniffSTUN reads a STUN message at the start of a stream: unframed, as to
// a STUN or TURN server (RFC 8489, section 6.2.2), or after the 2-byte
// length of RFC 4571, as ICE-TCP sends it (RFC 6544, section 7.1). It takes
// only messages with the magic cookie: classic STUN (RFC 3489) has none, and
// without it a header is a few bits any other datagram may carry.
//
// b may hold more than the message; SniffSTUNDatagram is for a datagram on
// its own.
func SniffSTUN(b []byte) (*SniffHeader, error) {
	start, n, err := 0, 0, error(nil)
	if n, err = message(b); err == errNotSTUN {
		start, n, err = framed(b)
	}
	if err != nil {
		return nil, err
	}
	if n > MaxMessageLen {
		return nil, errNotSTUN
	}
	if start+n > len(b) {
		// The cookie is in place, so it is STUN: wait for the rest.
		return nil, protocol.ErrProtoNeedMoreData
	}
	if !attributes(b[start+headerLen : start+n]) {
		return nil, errNotSTUN
	}
	return &SniffHeader{}, nil
}

// framed checks a message after an RFC 4571 length, which must be the
// message's, and returns where the message starts and its length.
func framed(b []byte) (int, int, error) {
	const lengthLen = 2
	if len(b) > lengthLen && b[lengthLen]&0xC0 != 0 {
		return 0, 0, errNotSTUN
	}
	if len(b) < lengthLen+8 {
		return 0, 0, common.ErrNoClue
	}
	n, err := message(b[lengthLen:])
	if err != nil {
		return 0, 0, err
	}
	if int(binary.BigEndian.Uint16(b)) != n {
		return 0, 0, errNotSTUN
	}
	return lengthLen, n, nil
}

// SniffSTUNDatagram reads a datagram that is one STUN message, as it is over
// UDP: its length says where the datagram ends.
func SniffSTUNDatagram(d []byte) (*SniffHeader, error) {
	n, err := message(d)
	if err == common.ErrNoClue {
		// A datagram is whole: one too short for the header is no STUN.
		return nil, errNotSTUN
	}
	if err != nil {
		return nil, err
	}
	if n != len(d) || !attributes(d[headerLen:]) {
		return nil, errNotSTUN
	}
	return &SniffHeader{}, nil
}

// message checks the header at the start of b and returns the length of the
// whole message.
func message(b []byte) (int, error) {
	if len(b) > 0 && b[0]&0xC0 != 0 {
		return 0, errNotSTUN
	}
	if len(b) < 8 {
		return 0, common.ErrNoClue
	}
	if binary.BigEndian.Uint32(b[4:8]) != magicCookie {
		return 0, errNotSTUN
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length%4 != 0 {
		return 0, errNotSTUN
	}
	return headerLen + length, nil
}

// attributes reports whether b is a run of attributes that ends where b does.
func attributes(b []byte) bool {
	for len(b) > 0 {
		if len(b) < 4 {
			return false
		}
		size := 4 + (int(binary.BigEndian.Uint16(b[2:4]))+3)&^3
		if size > len(b) {
			return false
		}
		b = b[size:]
	}
	return true
}
