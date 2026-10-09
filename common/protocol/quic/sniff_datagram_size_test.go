package quic_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/quic"
)

// RFC 9000 bounds a datagram that carries an Initial packet only from below,
// at 1200 bytes (Section 14.1). A client may send a longer one when it
// believes the path and the server take it, up to the 65527 bytes of a UDP
// payload (Sections 14 and 18.2). Servers read datagrams into buffers of
// their own size: quic-go reads the first 1452 bytes of each and parses what
// fits (sys_conn.go, sys_conn_oob.go), x/net/quic the first 1472 (quic.go),
// nginx the whole datagram. Nor do they count the 1200 bytes alike: nginx
// drops an Initial packet coalesced after another when fewer than 1200 bytes
// of the datagram start with it. The sniffer reads each datagram the
// dispatcher forwards whole, and every coalesced packet in it.
//
// quicGoBuffer only models the read path of quic-go, to show where what it
// reads parts ways with what the sniffer reads. It is no rule of QUIC, and the
// sniffer must not apply it.
const quicGoBuffer = 1452

// packetCut is the outcome of a flow whose first packet runs past the end of
// its datagram: the sniffer has no decision.
const packetCut = "packet cut by the end of its datagram"

// datagramOutcome classifies what quic.SniffQUICDatagrams returned.
func datagramOutcome(header *quic.SniffHeader, err error) outcome {
	if errors.Is(err, common.ErrNoClue) {
		return outcome{class: packetCut}
	}
	return sniffDatagramsOutcome(header, err)
}

// decide sniffs datagrams as the dispatcher does, once more after each one
// arrives, and returns the first decision: a server name, or an error that
// ends sniffing. Without one, it returns what all the datagrams yield.
func decide(datagrams [][]byte) outcome {
	var o outcome
	for i := range datagrams {
		o = datagramOutcome(quic.SniffQUICDatagrams(datagrams[:i+1]))
		if o.class != needMore && o.class != packetCut {
			return o
		}
	}
	return o
}

// readByQuicGo returns what the read path of quic-go keeps of each datagram.
func readByQuicGo(datagrams [][]byte) [][]byte {
	read := make([][]byte, len(datagrams))
	for i, datagram := range datagrams {
		read[i] = datagram[:min(len(datagram), quicGoBuffer)]
	}
	return read
}

// initialOverhead is what an Initial packet sealed by sealInitialPacket adds
// to its frames: a long header with destConnID, no Source Connection ID, no
// token and a 2-byte Length, a 4-byte packet number and the AEAD tag.
func initialOverhead(destConnID []byte) int {
	return 1 + 4 + 1 + len(destConnID) + 1 + 1 + 2 + 4 + 16
}

// initialOfSize seals an Initial packet of exactly size bytes that carries
// frames and PADDING frames after them, or before them if paddingFirst.
func initialOfSize(t testing.TB, destConnID []byte, pn uint64, frames []byte, size int, paddingFirst bool) []byte {
	t.Helper()
	padding := size - initialOverhead(destConnID) - len(frames)
	if padding < 0 {
		t.Fatalf("%d bytes of frames do not fit in a packet of %d bytes", len(frames), size)
	}
	var payload []byte
	if paddingFirst {
		payload = append(make([]byte, padding), frames...)
	} else {
		payload = append(bytes.Clone(frames), make([]byte, padding)...)
	}
	packet := sealInitialPacket(t, destConnID, pn, 4, payload)
	if len(packet) != size {
		t.Fatalf("sealed a packet of %d bytes, want %d", len(packet), size)
	}
	return packet
}

// datagramSizes returns the length of each datagram.
func datagramSizes(datagrams [][]byte) []int {
	sizes := make([]int, len(datagrams))
	for i, datagram := range datagrams {
		sizes[i] = len(datagram)
	}
	return sizes
}

// sizeCase is a flow of datagrams, with what the sniffer must decide from the
// datagrams as sent and from what quic-go reads of them.
type sizeCase struct {
	group, name string
	datagrams   [][]byte
	want        outcome
	quicGo      outcome
}

// datagramSizeCases builds the flows of TestSniffQUICDatagramSizes. The client
// of the connection with destConnID names allowed; blocked is another server
// name of the same length, and otherConnID another connection.
func datagramSizeCases(t *testing.T, allowed, blocked string, destConnID, otherConnID []byte) []sizeCase {
	t.Helper()
	if len(allowed) != len(blocked) {
		t.Fatalf("%q and %q differ in length", allowed, blocked)
	}
	hello := smallQUICClientHello(t, allowed)
	n := len(hello)
	// blockedHello differs from hello in its server name alone.
	nameStart := bytes.Index(hello, []byte(allowed))
	nameEnd := nameStart + len(allowed)
	blockedHello := bytes.Replace(hello, []byte(allowed), []byte(blocked), 1)
	whole := appendCryptoFrames(nil, cryptoFrame{0, hello})
	part := func(from, to int) []byte {
		return appendCryptoFrames(nil, cryptoFrame{from, hello[from:to]})
	}
	ours := func(pn uint64, frames []byte, size int) []byte {
		return initialOfSize(t, destConnID, pn, frames, size, false)
	}
	// minimal is the size of a packet carrying the whole ClientHello alone.
	minimal := initialOverhead(destConnID) + len(whole)
	if minimal >= 1200 || 2*minimal > 1498-200 {
		t.Fatalf("the ClientHello takes a packet of %d bytes", minimal)
	}

	named := func(name string) outcome { return outcome{domain: name} }
	allowedName, blockedName := named(allowed), named(blocked)
	more, cut := outcome{class: needMore}, outcome{class: packetCut}
	// quicGoReads is want while the packet that carries the ClientHello ends
	// within the buffer of quic-go, and otherwise a packet cut short.
	quicGoReads := func(want outcome, packetEnd int) outcome {
		if packetEnd > quicGoBuffer {
			return cut
		}
		return want
	}

	var cases []sizeCase
	add := func(group, name string, want, quicGo outcome, datagrams ...[]byte) {
		cases = append(cases, sizeCase{group, name, datagrams, want, quicGo})
	}

	const valid = "1 valid Initial datagram"
	for _, size := range []int{1200, 1451, 1452, 1453, 1472, 1473, 1498, 9000} {
		add(valid, fmt.Sprintf("%d bytes", size), allowedName, quicGoReads(allowedName, size), ours(0, whole, size))
	}
	// The ClientHello crypto/tls sends with X25519MLKEM768 fills more than
	// 1452 bytes. A client may send it in one Initial packet.
	mlkem := appendCryptoFrames(nil, cryptoFrame{0, quicTLSClientHello(t, allowed)})
	mlkemSize := initialOverhead(destConnID) + len(mlkem)
	add(valid, fmt.Sprintf("X25519MLKEM768 ClientHello in one packet of %d bytes", mlkemSize), allowedName, quicGoReads(allowedName, mlkemSize), ours(0, mlkem, mlkemSize))

	const padding = "2 the same ClientHello padded"
	for _, size := range []int{1200, 1451, 1452, 1453, 1498} {
		add(padding, fmt.Sprintf("with PADDING frames before its CRYPTO frame to %d bytes", size), allowedName, quicGoReads(allowedName, size),
			initialOfSize(t, destConnID, 0, whole, size, true))
		add(padding, fmt.Sprintf("with zeros after its packet of %d bytes to %d bytes", minimal, size), allowedName, allowedName,
			padTo(ours(0, whole, minimal), size))
	}
	for _, packetSize := range []int{1200, 1452, 1453} {
		add(padding, fmt.Sprintf("with zeros after its packet of %d bytes to 1498 bytes", packetSize), allowedName, quicGoReads(allowedName, packetSize),
			padTo(ours(0, whole, packetSize), 1498))
	}

	const incomplete = "3 incomplete ClientHello"
	add(incomplete, "one byte short, in 1498 bytes", more, cut, ours(0, part(0, n-1), 1498))
	add(incomplete, "up to the end of its server name, in 1498 bytes", more, cut, ours(0, part(0, nameEnd), 1498))
	add(incomplete, "up to the end of its server name, in 1452 bytes", more, more, ours(0, part(0, nameEnd), 1452))
	add(incomplete, "packet of 1498 bytes cut after 1452", cut, cut, ours(0, whole, 1498)[:1452])
	add(incomplete, "packet of 1498 bytes cut after 1497", cut, cut, ours(0, whole, 1498)[:1497])

	const after = "4 bytes after the Initial packet"
	add(after, "junk after a packet of 1200 bytes, 1498 bytes", allowedName, allowedName,
		slices.Concat(ours(0, whole, 1200), bytes.Repeat([]byte{0x5a}, 298)))
	add(after, "a cut packet of the connection after one of 1200 bytes, 1498 bytes", allowedName, allowedName,
		slices.Concat(ours(0, whole, 1200), ours(1, whole, 1200)[:298]))
	add(after, "another connection's Initial packet naming "+blocked+", 1498 bytes", allowedName, allowedName,
		slices.Concat(ours(0, whole, minimal), initialOfSize(t, otherConnID, 0, appendCryptoFrames(nil, cryptoFrame{0, blockedHello}), 1498-minimal, false)))
	add(after, "a 0-RTT packet of the connection, 1498 bytes", allowedName, allowedName,
		padTo(slices.Concat(ours(0, whole, minimal), zeroRTTPacket(destConnID)), 1498))
	add(after, "a second ClientHello naming "+blocked+", 1498 bytes", allowedName, allowedName,
		slices.Concat(ours(0, whole, minimal), ours(1, appendCryptoFrames(nil, cryptoFrame{0, blockedHello}), 1498-minimal)))
	add(after, "junk after a packet with the start of the ClientHello, 1498 bytes, then the rest", allowedName, allowedName,
		slices.Concat(ours(0, part(0, nameEnd), 1200), bytes.Repeat([]byte{0x5a}, 298)), ours(1, part(nameEnd, n), 1200))
	startOnly := initialOverhead(destConnID) + len(part(0, nameEnd))
	add(after, fmt.Sprintf("zeros after a packet of %d bytes with the start of the ClientHello, 1498 bytes, then the rest", startOnly), allowedName, allowedName,
		padTo(ours(0, part(0, nameEnd), startOnly), 1498), ours(1, part(nameEnd, n), 1200))
	add(after, "the end of the ClientHello in a packet past byte 1452, 1498 bytes", allowedName, more,
		slices.Concat(ours(0, part(0, nameEnd), 1000), ours(1, part(nameEnd, n), 498)))

	const boundaries = "5 datagram boundaries"
	for _, sizes := range [][2]int{{1498, 1498}, {1452, 1452}, {1452, 1453}, {1453, 1452}} {
		quicGo := allowedName
		switch {
		case sizes[0] > quicGoBuffer:
			quicGo = cut
		case sizes[1] > quicGoBuffer:
			quicGo = more
		}
		add(boundaries, fmt.Sprintf("ClientHello over datagrams of %d and %d bytes", sizes[0], sizes[1]), allowedName, quicGo,
			ours(0, part(0, nameEnd), sizes[0]), ours(1, part(nameEnd, n), sizes[1]))
	}
	// Concatenated, the two datagrams hold the packet whole.
	running := ours(0, part(0, nameEnd), 1538)
	add(boundaries, "a packet running from a datagram of 1498 bytes into the next", cut, cut,
		running[:1498], slices.Concat(running[1498:], ours(1, part(nameEnd, n), 1200)))

	const apart = "6 servers part ways"
	add(apart, "whole ClientHello in 1498 bytes, then one naming "+blocked, allowedName, cut,
		ours(0, whole, 1498), ours(1, appendCryptoFrames(nil, cryptoFrame{0, blockedHello}), 1210))
	add(apart, "ClientHello ending past byte 1452, then another end naming "+blocked, allowedName, blockedName,
		slices.Concat(ours(0, part(0, nameStart), 1000), ours(1, part(nameStart, n), 498)),
		ours(2, appendCryptoFrames(nil, cryptoFrame{nameStart, blockedHello[nameStart:]}), 1200))
	add(apart, "ClientHello ending in a coalesced packet of 600 bytes, then another end naming "+blocked, allowedName, allowedName,
		slices.Concat(ours(0, part(0, nameStart), 600), ours(1, part(nameStart, n), 600)),
		ours(2, appendCryptoFrames(nil, cryptoFrame{nameStart, blockedHello[nameStart:]}), 1200))

	const none = "7 no server name is the safe answer"
	add(none, "the start of one ClientHello in 1498 bytes, then another whole", outcome{class: conflict}, cut,
		ours(0, part(0, nameEnd), 1498), ours(1, appendCryptoFrames(nil, cryptoFrame{0, blockedHello}), 1210))
	add(none, "the rest of the ClientHello in a short datagram once started", outcome{class: shortDatagram}, outcome{class: shortDatagram},
		ours(0, part(0, nameEnd), 1200), ours(1, part(nameEnd, n), initialOverhead(destConnID)+len(part(nameEnd, n))))
	return cases
}

// The sniffer reads a valid Initial datagram of any size whole and names the
// server of a whole ClientHello in it, whatever padding surrounds it. It names
// no server before the whole ClientHello has arrived, from a packet cut
// short, or when the bytes of two ClientHellos meet. Where servers read a
// flow differently (group 6), it sides with none of their buffer sizes or
// counts, and names the server a whole reading of the datagrams gives. Each
// flow is also sniffed as quic-go reads it, which only shows where the two
// part ways.
func TestSniffQUICDatagramSizes(t *testing.T) {
	for _, tt := range datagramSizeCases(t, "allowed.example", "blocked.example", reassemblyDestConnID, foreignDestConnID) {
		t.Run(tt.group+"/"+tt.name, func(t *testing.T) {
			got := decide(tt.datagrams)
			if got != tt.want {
				t.Errorf("from the datagrams as sent: %v, want %v", got, tt.want)
			}
			gotQuicGo := decide(readByQuicGo(tt.datagrams))
			if gotQuicGo != tt.quicGo {
				t.Errorf("from what quic-go reads of them: %v, want %v", gotQuicGo, tt.quicGo)
			}
			t.Logf("datagrams %v: as sent %v; as quic-go reads them %v", datagramSizes(tt.datagrams), got, gotQuicGo)
		})
	}
}

// The sniffer names a server once the whole ClientHello has arrived, and not
// before: wherever the ClientHello is cut, in one datagram of 1498 bytes or
// split over two, and wherever the end of its datagram cuts a packet.
func TestSniffQUICNamesOnlyWholeClientHellos(t *testing.T) {
	const name = "allowed.example"
	hello := smallQUICClientHello(t, name)
	for k := 1; k < len(hello); k++ {
		first := initialOfSize(t, reassemblyDestConnID, 0, appendCryptoFrames(nil, cryptoFrame{0, hello[:k]}), 1498, false)
		if got := datagramOutcome(quic.SniffQUICDatagrams([][]byte{first})); got.class != needMore {
			t.Fatalf("ClientHello cut after %d of %d bytes: %v, want %s", k, len(hello), got, needMore)
		}
		second := initialOfSize(t, reassemblyDestConnID, 1, appendCryptoFrames(nil, cryptoFrame{k, hello[k:]}), 1498, false)
		if got := datagramOutcome(quic.SniffQUICDatagrams([][]byte{first, second})); got != (outcome{domain: name}) {
			t.Fatalf("ClientHello split after %d bytes over two datagrams: %v, want server name %q", k, got, name)
		}
	}
	packet := initialOfSize(t, reassemblyDestConnID, 0, appendCryptoFrames(nil, cryptoFrame{0, hello}), 1498, false)
	for size := 1; size < len(packet); size++ {
		if got := datagramOutcome(quic.SniffQUICDatagrams([][]byte{packet[:size]})); got.domain != "" {
			t.Fatalf("packet cut after %d of %d bytes: %v, want no server name", size, len(packet), got)
		}
	}
}
