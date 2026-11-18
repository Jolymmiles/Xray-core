// Package discord sniffs the IP discovery request of Discord voice: the
// first datagram a Discord client sends to a voice server, before the RTP of
// a call, a stream or screen sharing follows on the same pair of ports, so a
// rule on it routes the whole call. Discord in a browser speaks WebRTC
// instead, which the STUN sniffer takes.
//
// The rule holds for the UDP flow the request opens, as for every sniffer
// that reads the first datagram. A flow reopened mid-call, after an idle
// timeout or a reconnect, starts with RTP and takes the default route. On a
// full-cone association the flow is keyed without its destination, so what
// the same socket sends elsewhere takes the route the request chose.
package discord

import (
	"errors"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "discordrtc"
}

func (h *SniffHeader) Domain() string {
	return ""
}

// The IP discovery packet of Discord voice:
//
//	0-1      type: 1 for a request, 2 for the response
//	2-3      length of what follows the type and this field: 70
//	4-7      SSRC
//	8-71     address, a null-terminated string, empty in a request
//	72-73    port
//
// It shares its first two bytes with a STUN binding request, but its length
// of 70 is no multiple of 4 and the SSRC stands where STUN has its cookie, so
// the STUN sniffer leaves it.
const (
	packetLen  = 74
	addressEnd = 72
)

var errNotDiscord = errors.New("not discord")

// SniffIPDiscovery reads a datagram that is one IP discovery request: its
// type, length and empty address. The SSRC and the port vary from one call to
// the next.
func SniffIPDiscovery(d []byte) (*SniffHeader, error) {
	if len(d) != packetLen || d[0] != 0 || d[1] != 1 || d[2] != 0 || d[3] != 70 {
		return nil, errNotDiscord
	}
	for _, c := range d[8:addressEnd] {
		if c != 0 {
			return nil, errNotDiscord
		}
	}
	return &SniffHeader{}, nil
}
