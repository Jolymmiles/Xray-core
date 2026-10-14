package quic_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common/protocol/quic"
)

// The classes of SniffQUICDatagrams errors for datagrams servers do not read
// alike.
const (
	notFirstPacket = "first Initial packet after another packet of its datagram"
	partWays       = "Initial packet after one some servers stop reading its datagram at"
)

// assertSniffBoth checks that SniffQUICDatagrams yields want from datagrams,
// and that SniffQUIC yields it from them concatenated, as the header rules of
// a packet hold for both.
func assertSniffBoth(t *testing.T, datagrams [][]byte, want outcome) {
	t.Helper()
	if got := sniffDatagramsOutcome(quic.SniffQUICDatagrams(datagrams)); got != want {
		t.Errorf("SniffQUICDatagrams() yields %v, want %v", got, want)
	}
	if got := sniffOutcome(quic.SniffQUIC(bytes.Join(datagrams, nil))); got != want {
		t.Errorf("SniffQUIC() yields %v, want %v", got, want)
	}
}

// A server starts a connection only from an Initial packet in a datagram of
// at least 1200 bytes (RFC 9000, Section 14.1) that is the first packet of the
// datagram: quic-go and x/net/quic check both before they create one. The
// client sent the packets of such a datagram for no server to read them, so
// the sniffer ends sniffing at once, without a server name, rather than wait
// for a datagram a server reads. A datagram without an Initial packet starts
// nothing and changes nothing, as before.
func TestSniffQUICDatagramsStartTheConnectionAsServersDo(t *testing.T) {
	const name, otherName = "start.sniff.test", "other.sniff.test"
	ours := sealInitialPacket(t, reassemblyDestConnID, 0, 4, appendCryptoFrames(nil, cryptoFrame{0, smallQUICClientHello(t, name)}))
	theirs := sealInitialPacket(t, foreignDestConnID, 0, 4, appendCryptoFrames(nil, cryptoFrame{0, smallQUICClientHello(t, otherName)}))
	tests := []struct {
		name      string
		datagrams [][]byte
		want      outcome
	}{
		{"Initial packet in a datagram of 1200 bytes", [][]byte{padTo1200(ours)}, outcome{domain: name}},
		{"Initial packet in a datagram of 1199 bytes", [][]byte{padTo(ours, 1199)}, outcome{class: shortDatagram}},
		{"Initial packet in a short datagram, then one in a datagram of 1200 bytes", [][]byte{
			ours, padTo1200(theirs),
		}, outcome{class: shortDatagram}},
		{"Initial packet after a 0-RTT packet of its connection", [][]byte{
			padTo1200(slices.Concat(zeroRTTPacket(reassemblyDestConnID), ours)),
		}, outcome{class: notFirstPacket}},
		{"Initial packet after a Handshake packet of its connection", [][]byte{
			padTo1200(slices.Concat(longHeaderPacket(0xe3, 1, reassemblyDestConnID), ours)),
		}, outcome{class: notFirstPacket}},
		{"Initial packet after a 0-RTT packet of another connection", [][]byte{
			padTo1200(slices.Concat(zeroRTTPacket(foreignDestConnID), ours)),
		}, outcome{class: notFirstPacket}},
		{"a 0-RTT packet alone, then an Initial packet", [][]byte{
			padTo1200(zeroRTTPacket(reassemblyDestConnID)), padTo1200(ours),
		}, outcome{domain: name}},
		{"a short datagram without an Initial packet, then an Initial packet", [][]byte{
			zeroRTTPacket(reassemblyDestConnID), padTo1200(ours),
		}, outcome{domain: name}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sniffDatagramsOutcome(quic.SniffQUICDatagrams(tt.datagrams)); got != tt.want {
				t.Fatalf("SniffQUICDatagrams() yields %v, want %v", got, tt.want)
			}
		})
	}
}

// The header of an Initial packet decides whether servers read it, wherever
// the datagram boundaries are:
//
//   - A connection ID of a QUIC v1 or v2 long header packet has at most 20
//     bytes; a server drops a packet with a longer one (RFC 9000, Section
//     17.2; quic-go, x/net/quic).
//   - The reserved bits of the first byte must be 0 once the protection is
//     removed, or the server closes the connection (RFC 9000, Section 17.2;
//     quic-go, x/net/quic): no server reads its ClientHello.
//   - A client's first Destination Connection ID has at least 8 bytes (RFC
//     9000, Section 7.2). quic-go drops a first Initial packet with a shorter
//     one and x/net/quic reads it, so servers part ways and the sniffer names
//     no server.
func TestSniffQUICReadsInitialPacketHeadersAsServersDo(t *testing.T) {
	const name = "header.sniff.test"
	whole := appendCryptoFrames(nil, cryptoFrame{0, smallQUICClientHello(t, name)})
	seal := func(p initialPacket) []byte {
		p.pnLength, p.payload = 4, whole
		return padTo1200(p.seal(t))
	}
	connID := func(n int) []byte {
		return bytes.Repeat([]byte{0x5c}, n)
	}
	tests := []struct {
		name   string
		packet initialPacket
		want   outcome
	}{
		{"Destination Connection ID of 8 bytes", initialPacket{destConnID: connID(8)}, outcome{domain: name}},
		{"Destination Connection ID of 20 bytes", initialPacket{destConnID: connID(20)}, outcome{domain: name}},
		{"Destination Connection ID of 21 bytes", initialPacket{destConnID: connID(21)}, outcome{class: notQUIC}},
		{"Destination Connection ID of 7 bytes", initialPacket{destConnID: connID(7)}, outcome{class: shortDestConnID}},
		{"empty Destination Connection ID", initialPacket{destConnID: connID(0)}, outcome{class: shortDestConnID}},
		{"Source Connection ID of 20 bytes", initialPacket{destConnID: connID(8), srcConnID: connID(20)}, outcome{domain: name}},
		{"Source Connection ID of 21 bytes", initialPacket{destConnID: connID(8), srcConnID: connID(21)}, outcome{class: notQUIC}},
		{"first reserved bit set", initialPacket{destConnID: connID(8), reserved: 0b10}, outcome{class: reservedBits}},
		{"second reserved bit set", initialPacket{destConnID: connID(8), reserved: 0b01}, outcome{class: reservedBits}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSniffBoth(t, [][]byte{seal(tt.packet)}, tt.want)
		})
	}

	// The reserved bits of a later packet of the connection close it too.
	hello := smallQUICClientHello(t, name)
	middle := len(hello) / 2
	part := func(pn uint64, reserved byte, from, to int) []byte {
		return padTo1200(initialPacket{
			destConnID: reassemblyDestConnID, reserved: reserved, pn: pn, pnLength: 4,
			payload: appendCryptoFrames(nil, cryptoFrame{from, hello[from:to]}),
		}.seal(t))
	}
	t.Run("reserved bits set in a later packet", func(t *testing.T) {
		assertSniffBoth(t, [][]byte{part(0, 0, 0, middle), part(1, 0b11, middle, len(hello))}, outcome{class: reservedBits})
	})
	t.Run("reserved bits clear in every packet", func(t *testing.T) {
		assertSniffBoth(t, [][]byte{part(0, 0, 0, middle), part(1, 0, middle, len(hello))}, outcome{domain: name})
	})
}

// A server discards a later Initial packet of the connection whose Source
// Connection ID differs from the one of the first (RFC 9000, Section 7.2):
// quic-go does, x/net/quic does not. A client keeps its Source Connection ID,
// so a flow that changes it is crafted to have servers read different
// ClientHellos, and the sniffer names no server.
func TestSniffQUICKeepsTheSourceConnectionID(t *testing.T) {
	const allowed, blocked = "allowed.example", "blocked.example"
	hello := smallQUICClientHello(t, allowed)
	nameStart := bytes.Index(hello, []byte(allowed))
	blockedHello := bytes.Replace(hello, []byte(allowed), []byte(blocked), 1)
	first, other := []byte{0x51, 0x52, 0x53, 0x54}, []byte{0x61, 0x62, 0x63, 0x64}
	packet := func(pn uint64, srcConnID, hello []byte, from, to int) []byte {
		return padTo1200(initialPacket{
			destConnID: reassemblyDestConnID, srcConnID: srcConnID, pn: pn, pnLength: 4,
			payload: appendCryptoFrames(nil, cryptoFrame{from, hello[from:to]}),
		}.seal(t))
	}
	start := packet(0, first, hello, 0, nameStart)
	t.Run("the rest of the ClientHello from another Source Connection ID", func(t *testing.T) {
		// quic-go discards the second datagram and reads the third, naming
		// blocked.example; x/net/quic reads the second, naming allowed.example.
		assertSniffBoth(t, [][]byte{
			start, packet(1, other, hello, nameStart, len(hello)), packet(2, first, blockedHello, nameStart, len(hello)),
		}, outcome{class: otherSourceConnID})
	})
	t.Run("the rest of the ClientHello from the same Source Connection ID", func(t *testing.T) {
		assertSniffBoth(t, [][]byte{start, packet(1, first, hello, nameStart, len(hello))}, outcome{domain: allowed})
	})
}

// Servers part ways on the packets of a datagram after some packets: quic-go
// stops reading the datagram at a packet of another connection or version,
// which lsquic, picoquic and quicly skip; x/net/quic, quiche and ngtcp2 stop
// at a packet of the connection that does not decrypt, which quic-go and
// picoquic skip; quiche, ngtcp2 and picoquic stop at a repeated packet, which
// quic-go and x/net/quic skip; x/net/quic stops at a 0-RTT packet, which
// quic-go queues. An Initial packet of the connection that is new after such
// a packet ends sniffing without a server name. Valid clients send none of
// these datagrams: they coalesce packets of one connection and version only
// (RFC 9000, Section 12.2), in the order of their encryption levels, and never
// repeat a packet number.
func TestSniffQUICDatagramsStopWhereServersPartWays(t *testing.T) {
	const name = "apart.sniff.test"
	hello := smallQUICClientHello(t, name)
	middle := len(hello) / 2
	ours := func(pn uint64, from, to int) []byte {
		return sealInitialPacket(t, reassemblyDestConnID, pn, 4, appendCryptoFrames(nil, cryptoFrame{from, hello[from:to]}))
	}
	first, second := ours(0, 0, middle), ours(1, middle, len(hello))
	between := func(packet []byte) [][]byte {
		return [][]byte{padTo1200(slices.Concat(first, packet, second))}
	}
	tests := []struct {
		name      string
		datagrams [][]byte
		want      outcome
	}{
		{"nothing between two Initial packets", between(nil), outcome{domain: name}},
		{"a Handshake packet of the connection between them", between(longHeaderPacket(0xe3, 1, reassemblyDestConnID)), outcome{domain: name}},
		{"a packet of another connection between them", between(undecryptableInitial(foreignDestConnID)), outcome{class: partWays}},
		{"a QUIC v2 packet of the connection between them", between(longHeaderPacket(0xf3, 0x6b3343cf, reassemblyDestConnID)), outcome{class: partWays}},
		{"a packet of the connection that does not decrypt between them", between(undecryptableInitial(reassemblyDestConnID)), outcome{class: partWays}},
		{"a repeated packet between them", between(first), outcome{class: partWays}},
		{"a 0-RTT packet of the connection between them", between(zeroRTTPacket(reassemblyDestConnID)), outcome{class: partWays}},
		{"a repeated packet starting a later datagram", [][]byte{padTo1200(first), padTo1200(slices.Concat(first, second))}, outcome{class: partWays}},
		{"a repeated packet ending the datagram", [][]byte{padTo1200(slices.Concat(first, second, first))}, outcome{domain: name}},
		{"a packet that does not decrypt ending one datagram, the rest in the next", [][]byte{
			padTo1200(slices.Concat(first, undecryptableInitial(reassemblyDestConnID))), padTo1200(second),
		}, outcome{domain: name}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sniffDatagramsOutcome(quic.SniffQUICDatagrams(tt.datagrams)); got != tt.want {
				t.Fatalf("SniffQUICDatagrams() yields %v, want %v", got, tt.want)
			}
		})
	}
}

// The sniffer removes the protection of a packet in a buffer that holds the
// largest datagram, which need not be the first.
func TestSniffQUICDatagramsOpenPacketsOfLargerLaterDatagrams(t *testing.T) {
	const name = "grow.sniff.test"
	hello := smallQUICClientHello(t, name)
	middle := len(hello) / 2
	first := initialOfSize(t, reassemblyDestConnID, 0, appendCryptoFrames(nil, cryptoFrame{0, hello[:middle]}), 1200, false)
	second := initialOfSize(t, reassemblyDestConnID, 1, appendCryptoFrames(nil, cryptoFrame{middle, hello[middle:]}), 9000, false)
	if got := sniffDatagramsOutcome(quic.SniffQUICDatagrams([][]byte{first, second})); got != (outcome{domain: name}) {
		t.Fatalf("SniffQUICDatagrams() yields %v, want server name %q", got, name)
	}
}
