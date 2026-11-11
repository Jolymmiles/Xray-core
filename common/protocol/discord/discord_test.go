package discord_test

import (
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/protocol/discord"
	"github.com/xtls/xray-core/common/protocol/stun"
)

// request is an IP discovery request with its SSRC and port.
func request(ssrc uint32, port uint16) []byte {
	b := []byte{0x00, 0x01, 0x00, 0x46}
	b = binary.BigEndian.AppendUint32(b, ssrc)
	b = append(b, make([]byte, 64)...)
	return binary.BigEndian.AppendUint16(b, port)
}

func TestSniffIPDiscovery(t *testing.T) {
	for _, b := range [][]byte{request(0x0001e240, 0), request(0xffffffff, 50003), request(0, 0)} {
		header, err := discord.SniffIPDiscovery(b)
		if err != nil || header.Protocol() != "discordrtc" || header.Domain() != "" {
			t.Fatalf("SniffIPDiscovery(% x) = %v, %v; want discordrtc without a domain", b, header, err)
		}
	}
}

func TestSniffIPDiscoveryRejects(t *testing.T) {
	response := request(0x0001e240, 50003)
	response[1] = 2
	copy(response[8:], "203.0.113.7")
	address := request(0x0001e240, 0)
	address[8] = '1'
	lastAddressByte := request(0x0001e240, 0)
	lastAddressByte[71] = 1
	length := request(0x0001e240, 0)
	length[3] = 0x48
	for name, b := range map[string][]byte{
		"response":                response,
		"request with an address": address,
		"last address byte set":   lastAddressByte,
		"other length":            length,
		"zeros":                   make([]byte, 74),
		"one byte short":          request(1, 0)[:73],
		"one byte long":           append(request(1, 0), 0),
		"empty":                   nil,
	} {
		if header, err := discord.SniffIPDiscovery(b); err == nil {
			t.Errorf("%s: SniffIPDiscovery() = %v; want an error", name, header)
		}
	}
}

// The request opens like a STUN binding request but is none.
func TestIPDiscoveryIsNoSTUN(t *testing.T) {
	if header, err := stun.SniffSTUNDatagram(request(0x2112a442, 0)); err == nil {
		t.Fatalf("SniffSTUNDatagram() = %v; want an error", header)
	}
}
