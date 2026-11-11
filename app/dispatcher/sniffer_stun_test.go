package dispatcher

import (
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// stunBinding is an ICE binding request: USERNAME and PRIORITY.
func stunBinding() []byte {
	b := []byte{0x00, 0x01, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42}
	b = append(b, "transaction1"...)
	b = append(b, 0x00, 0x06, 0x00, 0x09)
	b = append(b, "evtj:h6vY\x00\x00\x00"...)
	return append(b, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff)
}

func sniffDatagrams(t *testing.T, network net.Network, datagrams ...[]byte) (SniffResult, error) {
	t.Helper()
	reader := newCachedReader(&datagramReader{datagrams: datagrams})
	ctx := snifferContext()
	return sniff(ctx, reader, false, network, newSniffer(ctx))
}

// A call's first datagram is a STUN check; DTLS and SRTP follow on the same
// ports.
func TestSniffSTUNFlow(t *testing.T) {
	dtls := []byte{0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20}
	for _, network := range []net.Network{net.Network_UDP, net.Network_TCP} {
		result, err := sniffDatagrams(t, network, stunBinding(), dtls)
		if err != nil || result.Protocol() != "stun" || result.Domain() != "" {
			t.Fatalf("%v: sniff() = %v, %v; want stun without a domain", network, result, err)
		}
	}
}

// Over TCP a message may come in pieces: the sniffer waits for the rest once
// the cookie is in.
func TestSniffSTUNOverTCPInPieces(t *testing.T) {
	b := stunBinding()
	result, err := sniffDatagrams(t, net.Network_TCP, b[:10], b[10:30], b[30:])
	if err != nil || result.Protocol() != "stun" {
		t.Fatalf("sniff() = %v, %v; want stun", result, err)
	}
}

// Over UDP the sniffer reads the first datagram on its own: a datagram with
// bytes after the message is no STUN message, though the same bytes in a
// stream would start with one.
func TestSniffSTUNReadsTheFirstDatagram(t *testing.T) {
	trailing := append(stunBinding(), 0, 0, 0, 0)
	if result, err := sniffDatagrams(t, net.Network_UDP, trailing); err == nil && result.Protocol() == "stun" {
		t.Fatal("a datagram longer than its STUN message taken for STUN")
	}
	split := stunBinding()
	if result, err := sniffDatagrams(t, net.Network_UDP, split[:20], split[20:]); err == nil && result.Protocol() == "stun" {
		t.Fatal("a STUN message split across datagrams taken for STUN")
	}
}

// The UDP sniffers that were there before STUN keep their flows.
func TestSniffSTUNLeavesOtherUDPFlows(t *testing.T) {
	dns := []byte{0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if result, err := sniffDatagrams(t, net.Network_UDP, dns); err == nil {
		t.Fatalf("a DNS query sniffed as %s", result.Protocol())
	}
	tracker := binary.BigEndian.AppendUint64(nil, 0x41727101980)
	tracker = append(tracker, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78)
	if result, err := sniffDatagrams(t, net.Network_UDP, tracker); err != nil || result.Protocol() != "bittorrent" {
		t.Fatalf("a UDP tracker connect sniffed as %v, %v; want bittorrent", result, err)
	}
	quic := readQUICCorpus(t, "quic-ngtcp2-1.11", 1)
	if result, err := sniffDatagrams(t, net.Network_UDP, quic...); err != nil || result.Protocol() != "quic" {
		t.Fatalf("a QUIC Initial sniffed as %v, %v; want quic", result, err)
	}
}

// A caller may hand the datagrams of an empty cache: the sniffer reads the
// payload then, and does not index the first datagram.
func TestSniffSTUNWithoutDatagrams(t *testing.T) {
	s := newSniffer(snifferContext())
	result, err := s.SniffDatagrams(snifferContext(), stunBinding(), [][]byte{}, net.Network_UDP)
	if err != nil || result.Protocol() != "stun" {
		t.Fatalf("SniffDatagrams() = %v, %v; want stun", result, err)
	}
}
