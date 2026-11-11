package dispatcher

import (
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// discordIPDiscovery is the IP discovery request a Discord client sends a
// voice server first.
func discordIPDiscovery() []byte {
	b := []byte{0x00, 0x01, 0x00, 0x46, 0x00, 0x01, 0xe2, 0x40}
	b = append(b, make([]byte, 64)...)
	return binary.BigEndian.AppendUint16(b, 0)
}

// A voice flow opens with IP discovery; RTP follows on the same ports.
func TestSniffDiscordRTCFlow(t *testing.T) {
	rtp := []byte{0x90, 0x78, 0x00, 0x01, 0x00, 0x00, 0x03, 0xc0, 0x00, 0x01, 0xe2, 0x40, 0xbe, 0xde, 0x00, 0x01}
	result, err := sniffDatagrams(t, net.Network_UDP, discordIPDiscovery(), rtp)
	if err != nil || result.Protocol() != "discordrtc" || result.Domain() != "" {
		t.Fatalf("sniff() = %v, %v; want discordrtc without a domain", result, err)
	}
}

// Over UDP the sniffer reads the first datagram on its own: the request split
// or followed by more bytes in the same datagram is none.
func TestSniffDiscordRTCReadsTheFirstDatagram(t *testing.T) {
	trailing := append(discordIPDiscovery(), 0, 0)
	if result, err := sniffDatagrams(t, net.Network_UDP, trailing); err == nil && result.Protocol() == "discordrtc" {
		t.Fatal("a datagram longer than the request taken for discordrtc")
	}
	split := discordIPDiscovery()
	if result, err := sniffDatagrams(t, net.Network_UDP, split[:8], split[8:]); err == nil && result.Protocol() == "discordrtc" {
		t.Fatal("a request split across datagrams taken for discordrtc")
	}
}

// Discord voice runs over UDP only.
func TestSniffDiscordRTCNotOverTCP(t *testing.T) {
	if result, err := sniffDatagrams(t, net.Network_TCP, discordIPDiscovery()); err == nil && result.Protocol() == "discordrtc" {
		t.Fatal("a TCP stream taken for discordrtc")
	}
}

// A caller may hand the datagrams of an empty cache: the sniffer reads the
// payload then.
func TestSniffDiscordRTCWithoutDatagrams(t *testing.T) {
	s := newSniffer(snifferContext())
	result, err := s.SniffDatagrams(snifferContext(), discordIPDiscovery(), [][]byte{}, net.Network_UDP)
	if err != nil || result.Protocol() != "discordrtc" {
		t.Fatalf("SniffDatagrams() = %v, %v; want discordrtc", result, err)
	}
}

// STUN, which Discord in a browser speaks, stays stun.
func TestSniffDiscordRTCLeavesSTUN(t *testing.T) {
	result, err := sniffDatagrams(t, net.Network_UDP, stunBinding())
	if err != nil || result.Protocol() != "stun" {
		t.Fatalf("a STUN binding sniffed as %v, %v; want stun", result, err)
	}
}
