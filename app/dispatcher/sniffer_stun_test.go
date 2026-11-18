package dispatcher

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
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
	reader := newTestCachedReader(t, &datagramReader{datagrams: datagrams})
	ctx := snifferContext()
	return sniff(ctx, reader, false, network, newSniffer(ctx))
}

// A call's first datagram is a STUN check; DTLS and SRTP follow on the same
// ports. sniff decides on the first datagram, before the DTLS one is read.
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

// SniffDatagrams gets an empty list when the cache holds several buffers and
// the first is longer than the scratch (default.go): there is no first
// datagram to read whole then, and a stream reader would take a datagram
// that only starts with a STUN message. A nil list is a caller without
// datagrams, which every datagram sniffer reads as a stream.
func TestSniffSTUNWithoutDatagrams(t *testing.T) {
	// A Sniffer keeps what is still pending: one per call.
	empty := newSniffer(snifferContext())
	if result, err := empty.SniffDatagrams(snifferContext(), stunBinding(), [][]byte{}, net.Network_UDP); err == nil && result.Protocol() == "stun" {
		t.Fatal("SniffDatagrams with an empty list took the payload for STUN")
	}
	none := newSniffer(snifferContext())
	if result, err := none.SniffDatagrams(snifferContext(), stunBinding(), nil, net.Network_UDP); err != nil || result.Protocol() != "stun" {
		t.Fatalf("SniffDatagrams without datagrams = %v, %v; want stun, read as a stream", result, err)
	}
}

// batchReader yields all its datagrams in one read, each in its own buffer:
// a link that queued several datagrams before the dispatcher read.
type batchReader struct{ datagrams [][]byte }

func (r *batchReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.datagrams) == 0 {
		return nil, buf.ErrReadTimeout
	}
	var mb buf.MultiBuffer
	for _, d := range r.datagrams {
		mb = append(mb, buf.FromBytes(bytes.Clone(d)))
	}
	r.datagrams = nil
	return mb, nil
}

func (r *batchReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

// A datagram longer than the scratch that starts with a STUN message, then a
// second, in one read: the cache hands no datagrams, and the payload is not
// STUN.
func TestSniffSTUNLongDatagramStartingWithAMessage(t *testing.T) {
	long := append(stunBinding(), make([]byte, 39064-len(stunBinding()))...)
	reader := newTestCachedReader(t, &batchReader{datagrams: [][]byte{long, stunBinding()}})
	ctx := snifferContext()
	if result, err := sniff(ctx, reader, false, net.Network_UDP, newSniffer(ctx)); err == nil && result.Protocol() == "stun" {
		t.Fatal("a 39064-byte datagram that starts with a STUN message taken for STUN")
	}
}

// ICE-TCP connectivity checks carry the RFC 4571 length before the message.
func TestSniffSTUNOverICETCP(t *testing.T) {
	m := stunBinding()
	framed := append(binary.BigEndian.AppendUint16(nil, uint16(len(m))), m...)
	result, err := sniffDatagrams(t, net.Network_TCP, framed)
	if err != nil || result.Protocol() != "stun" {
		t.Fatalf("an ICE-TCP binding request: sniff() = %v, %v; want stun", result, err)
	}
}
