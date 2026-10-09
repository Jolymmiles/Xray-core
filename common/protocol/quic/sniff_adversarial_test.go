package quic_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
	ptls "github.com/xtls/xray-core/common/protocol/tls"
)

// The tests in this file treat SniffQUIC as a state machine driven by an
// adversary: Initial keys derive from a connection ID the client chooses, so
// a client controls every frame of its Initial packets. They compare the
// sniffer with an independent model of the CRYPTO stream it reassembles.

const (
	// streamCap mirrors the sniffer's bound on CRYPTO stream offsets.
	streamCap = 32768
	// shortVarintMax mirrors the largest frame field the sniffer accepts.
	shortVarintMax = 65535
	// maxPacketPayload keeps a payload within the 2-byte Length field that
	// sealInitialPayload writes.
	maxPacketPayload = 16000
)

// outcome is what sniffing a flow yields: a server name, or a class of error.
type outcome struct {
	domain string
	class  string
}

func (o outcome) String() string {
	if o.class == "" {
		return fmt.Sprintf("server name %q", o.domain)
	}
	return o.class
}

const (
	needMore       = "more data needed"
	conflict       = "conflicting CRYPTO data"
	beyondCap      = "CRYPTO data beyond the stream cap"
	malformed      = "malformed frame"
	notClientHello = "not a ClientHello"
	noServerName   = "no server name"
	notInInitial   = "frame not allowed in Initial packets"
)

// sniffOutcome classifies what quic.SniffQUIC returned.
func sniffOutcome(header *quic.SniffHeader, err error) outcome {
	switch {
	case err == nil:
		return outcome{domain: header.Domain()}
	case errors.Is(err, protocol.ErrProtoNeedMoreData):
		return outcome{class: needMore}
	case errors.Is(err, io.ErrShortBuffer):
		return outcome{class: beyondCap}
	case errors.Is(err, io.ErrUnexpectedEOF):
		return outcome{class: malformed}
	}
	for _, c := range []struct{ text, class string }{
		{"CRYPTO frames carry different data", conflict},
		{"does not start with a ClientHello", notClientHello},
		{"no server name", noServerName},
		{"not initial packet", notInInitial},
	} {
		if strings.Contains(err.Error(), c.text) {
			return outcome{class: c.class}
		}
	}
	return outcome{class: "unexpected error " + err.Error()}
}

// frameSpec is a frame of a generated Initial packet: a CRYPTO frame, or any
// other frame encoded as is. invalid is the outcome class of a frame the
// sniffer must reject.
type frameSpec struct {
	crypto  bool
	offset  int
	data    []byte
	raw     []byte
	invalid string
	// last marks a frame that only parses as invalid at the end of a payload.
	last bool
}

// packetSpec is a generated Initial packet. A foreign packet carries another
// connection's Destination Connection ID.
type packetSpec struct {
	pn      uint32
	foreign bool
	frames  []frameSpec
}

var foreignDestConnID = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

// cryptoSpec returns a CRYPTO frame carrying data at offset.
func cryptoSpec(offset int, data []byte) frameSpec {
	return frameSpec{crypto: true, offset: offset, data: data}
}

// rawSpec returns a frame encoded as raw.
func rawSpec(raw ...byte) frameSpec {
	return frameSpec{raw: raw}
}

// invalidSpec returns a frame the sniffer must reject with class.
func invalidSpec(class string, last bool, raw ...byte) frameSpec {
	return frameSpec{raw: raw, invalid: class, last: last}
}

// packet returns an Initial packet of the connection.
func packet(pn uint32, frames ...frameSpec) packetSpec {
	return packetSpec{pn: pn, frames: frames}
}

// encodePayload encodes frames as the payload of an Initial packet.
func encodePayload(frames []frameSpec) []byte {
	var payload []byte
	for _, f := range frames {
		if f.crypto {
			payload = appendCryptoFrames(payload, cryptoFrame{f.offset, f.data})
		} else {
			payload = append(payload, f.raw...)
		}
	}
	return payload
}

// sealFlow protects packets and concatenates them, as the dispatcher hands
// its cached datagrams to the sniffer.
func sealFlow(tb testing.TB, packets []packetSpec) []byte {
	tb.Helper()
	var flow []byte
	for _, p := range packets {
		destConnID := reassemblyDestConnID
		if p.foreign {
			destConnID = foreignDestConnID
		}
		flow = append(flow, sealInitialPayload(tb, destConnID, p.pn, encodePayload(p.frames))...)
	}
	return flow
}

// referenceReassembly is an independent model of what SniffQUIC reads: the
// CRYPTO stream of the connection of the first packet, a packet whose number
// came before discarded (RFC 9000, Section 12.3), each byte kept as it first
// arrived and a repeat that differs rejected, data past the stream cap
// rejected, and the ClientHello read, after each packet, once all of it has
// arrived without a gap. It decides the server name with the TLS sniffer's
// ReadClientHello, which the QUIC sniffer shares.
func referenceReassembly(packets []packetSpec) outcome {
	var received [streamCap]bool
	var stream [streamCap]byte
	end := 0
	seen := map[uint32]bool{}
	for _, p := range packets {
		if p.foreign != packets[0].foreign || seen[p.pn] {
			continue
		}
		seen[p.pn] = true
		for _, f := range p.frames {
			if !f.crypto {
				if f.invalid != "" {
					return outcome{class: f.invalid}
				}
				continue
			}
			if f.offset > shortVarintMax || len(f.data) > shortVarintMax {
				return outcome{class: malformed}
			}
			if frameEnd := f.offset + len(f.data); frameEnd > end {
				if frameEnd > streamCap {
					return outcome{class: beyondCap}
				}
				end = frameEnd
			}
			for i, b := range f.data {
				at := f.offset + i
				switch {
				case !received[at]:
					received[at], stream[at] = true, b
				case stream[at] != b:
					return outcome{class: conflict}
				}
			}
		}
		prefix := 0
		for prefix < end && received[prefix] {
			prefix++
		}
		if prefix < 4 {
			continue
		}
		helloLen := 4 + (int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3]))
		if stream[0] != 1 || helloLen > streamCap {
			return outcome{class: notClientHello}
		}
		if prefix < helloLen {
			continue
		}
		var header ptls.SniffHeader
		if err := ptls.ReadClientHello(stream[:helloLen], &header); err != nil {
			return outcome{class: noServerName}
		}
		return outcome{domain: header.Domain()}
	}
	return outcome{class: needMore}
}

// readReferenceVarint reads a variable-length integer (RFC 9000, Section 16).
func readReferenceVarint(b []byte) (uint64, []byte, bool) {
	if len(b) == 0 {
		return 0, b, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, b, false
	}
	v := uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, b[n:], true
}

// parseReferenceFrames parses the frames of a decrypted Initial payload on
// its own (RFC 9000, Section 19), with the sniffer's limits: a frame type is
// one byte, and a frame field above 65535 is malformed. It stops at the first
// frame the sniffer must reject.
func parseReferenceFrames(payload []byte) []frameSpec {
	var frames []frameSpec
	field := func() (int, bool) {
		v, rest, ok := readReferenceVarint(payload)
		if !ok || v > shortVarintMax {
			return 0, false
		}
		payload = rest
		return int(v), true
	}
	fields := func(n int) bool {
		for range n {
			if _, ok := field(); !ok {
				return false
			}
		}
		return true
	}
	bad := func(class string) []frameSpec {
		return append(frames, frameSpec{invalid: class})
	}
	for len(payload) > 0 {
		frameType := payload[0]
		payload = payload[1:]
		switch frameType {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK
			if !fields(2) {
				return bad(malformed)
			}
			ranges, ok := field()
			if !ok || !fields(1+2*ranges) || frameType == 0x03 && !fields(3) {
				return bad(malformed)
			}
		case 0x06: // CRYPTO
			offset, ok := field()
			if !ok {
				return bad(malformed)
			}
			length, ok := field()
			if !ok || length > len(payload) {
				return bad(malformed)
			}
			frames = append(frames, cryptoSpec(offset, payload[:length]))
			payload = payload[length:]
		case 0x1c: // CONNECTION_CLOSE
			if !fields(2) {
				return bad(malformed)
			}
			reasonLen, ok := field()
			if !ok || reasonLen > len(payload) {
				return bad(malformed)
			}
			payload = payload[reasonLen:]
		default:
			return bad(notInInitial)
		}
	}
	return frames
}

// sniffAndCompare sniffs packets and checks the result against the model and,
// when want is not empty, against want. The flow must come out unmodified.
func sniffAndCompare(t *testing.T, packets []packetSpec, want *outcome) outcome {
	t.Helper()
	flow := sealFlow(t, packets)
	sent := bytes.Clone(flow)
	got := sniffOutcome(quic.SniffQUIC(flow))
	if !bytes.Equal(flow, sent) {
		t.Fatal("SniffQUIC modified the flow")
	}
	model := referenceReassembly(packets)
	if want != nil && model != *want {
		t.Fatalf("the model yields %v, want %v; the test case is wrong", model, *want)
	}
	if got != model {
		t.Fatalf("SniffQUIC yields %v, the model %v\n%s", got, model, describeFlow(packets))
	}
	return got
}

// describeFlow lists the frames of packets for a failure message.
func describeFlow(packets []packetSpec) string {
	var b strings.Builder
	for _, p := range packets {
		fmt.Fprintf(&b, "packet %d foreign=%v:", p.pn, p.foreign)
		for _, f := range p.frames {
			switch {
			case f.crypto:
				fmt.Fprintf(&b, " CRYPTO[%d,%d)", f.offset, f.offset+len(f.data))
			case f.invalid != "":
				fmt.Fprintf(&b, " invalid(% x)", f.raw)
			default:
				fmt.Fprintf(&b, " frame(% x)", f.raw)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// splitInto cuts data, which starts at offset, into CRYPTO frames of sizes,
// the last taking the rest.
func splitInto(offset int, data []byte, sizes ...int) []frameSpec {
	var frames []frameSpec
	for _, size := range sizes {
		size = min(size, len(data))
		frames = append(frames, cryptoSpec(offset, data[:size]))
		offset, data = offset+size, data[size:]
	}
	if len(data) > 0 {
		frames = append(frames, cryptoSpec(offset, data))
	}
	return frames
}

// evenly cuts data, which starts at offset, into n CRYPTO frames.
func evenly(offset int, data []byte, n int) []frameSpec {
	sizes := make([]int, n-1)
	for i := range sizes {
		sizes[i] = len(data) / n
	}
	return splitInto(offset, data, sizes...)
}

// eachInPacket puts each frame in a packet of its own, numbered from 0.
func eachInPacket(frames []frameSpec) []packetSpec {
	packets := make([]packetSpec, len(frames))
	for i, f := range frames {
		packets[i] = packet(uint32(i), f)
	}
	return packets
}

// padClientHello returns hello grown to total bytes by a padding extension
// (RFC 7685) at the end of its extensions.
func padClientHello(t *testing.T, hello []byte, total int) []byte {
	t.Helper()
	at := 4 + 2 + 32 // the legacy_session_id length
	at += 1 + int(hello[at])
	at += 2 + (int(hello[at])<<8 | int(hello[at+1]))
	at += 1 + int(hello[at]) // the extensions length follows
	padding := total - len(hello) - 4
	if padding < 0 || at+2 > len(hello) {
		t.Fatalf("cannot pad a %d-byte ClientHello to %d bytes", len(hello), total)
	}
	padded := slices.Concat(hello, []byte{0, 21, byte(padding >> 8), byte(padding)}, make([]byte, padding))
	extensions := (int(padded[at])<<8 | int(padded[at+1])) + 4 + padding
	padded[at], padded[at+1] = byte(extensions>>8), byte(extensions)
	body := len(padded) - 4
	padded[1], padded[2], padded[3] = byte(body>>16), byte(body>>8), byte(body)
	return padded
}

// spreadOver puts frames into packets numbered from 0 whose payloads stay
// within maxPacketPayload.
func spreadOver(frames []frameSpec) []packetSpec {
	var packets []packetSpec
	var current []frameSpec
	size := 0
	for _, f := range frames {
		n := len(encodePayload([]frameSpec{f}))
		if size+n > maxPacketPayload && len(current) > 0 {
			packets = append(packets, packet(uint32(len(packets)), current...))
			current, size = nil, 0
		}
		current = append(current, f)
		size += n
	}
	return append(packets, packet(uint32(len(packets)), current...))
}

// Each way a client can cut, order, repeat, overlap, change, leave out or
// extend its CRYPTO stream, with the outcome every RFC 9000 receiver that
// rejects differing repeats agrees on. The model must agree with each case
// too, so the randomized comparison below rests on a checked model.
func TestSniffQUICCryptoStreamEdgeCases(t *testing.T) {
	const name = "edge.sniff.test"
	hello := quicTLSClientHello(t, name)
	n := len(hello)
	other := bytes.Replace(hello, []byte(name), []byte("evil.sniff.test"), 1)
	nameAt := bytes.Index(hello, []byte(name))
	if nameAt < 0 || len(other) != n {
		t.Fatal("no server name to change in the ClientHello")
	}
	domain := outcome{domain: name}
	junk := bytes.Repeat([]byte{0xA5}, 300)
	reversed := func(frames []frameSpec) []frameSpec {
		frames = slices.Clone(frames)
		slices.Reverse(frames)
		return frames
	}
	shuffled := func(frames []frameSpec, seed uint64) []frameSpec {
		frames = slices.Clone(frames)
		rand.New(rand.NewPCG(seed, seed)).Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
		return frames
	}
	ones := make([]int, n)
	for i := range ones {
		ones[i] = 1
	}
	capHello := padClientHello(t, hello, streamCap)
	pastCapHello := padClientHello(t, hello, streamCap+1)
	encodedOffset := func(offset uint64) []byte { return quicvarint.Append(nil, offset) }
	ack := rawSpec(0x02, 0x05, 0x00, 0x01, 0x02, 0x00, 0x01)
	connectionClose := rawSpec(0x1c, 0x00, 0x00, 0x02, 'n', 'o')

	tests := []struct {
		name    string
		packets []packetSpec
		want    outcome
	}{
		{"ClientHello in one frame", []packetSpec{packet(0, cryptoSpec(0, hello))}, domain},
		{"two fragments", []packetSpec{packet(0, evenly(0, hello, 2)...)}, domain},
		{"three fragments", []packetSpec{packet(0, evenly(0, hello, 3)...)}, domain},
		{"ten fragments", []packetSpec{packet(0, evenly(0, hello, 10)...)}, domain},
		{"one-byte fragments", []packetSpec{packet(0, splitInto(0, hello, ones...)...)}, domain},
		{"reverse order", []packetSpec{packet(0, reversed(evenly(0, hello, 12))...)}, domain},
		{"random order", []packetSpec{packet(0, shuffled(evenly(0, hello, 40), 1)...)}, domain},
		{"fragments in packets of their own, last first", func() []packetSpec {
			packets := eachInPacket(evenly(0, hello, 11))
			slices.Reverse(packets)
			return packets
		}(), domain},
		{"decreasing packet numbers", []packetSpec{
			packet(9, cryptoSpec(2*n/3, hello[2*n/3:])),
			packet(4, cryptoSpec(n/3, hello[n/3:2*n/3])),
			packet(0, cryptoSpec(0, hello[:n/3])),
		}, domain},
		{"complete duplicate", []packetSpec{packet(0, cryptoSpec(0, hello), cryptoSpec(0, hello))}, domain},
		{"partly overlapping duplicates", []packetSpec{packet(0,
			cryptoSpec(0, hello[:n/2+17]), cryptoSpec(n/2-9, hello[n/2-9:n-5]), cryptoSpec(n-40, hello[n-40:]))}, domain},
		{"overlap that changes the server name", []packetSpec{packet(0,
			cryptoSpec(0, hello[:nameAt+2]), cryptoSpec(nameAt-3, other[nameAt-3:]))}, outcome{class: conflict}},
		{"large frame then a smaller one inside it", []packetSpec{packet(0,
			cryptoSpec(0, hello), cryptoSpec(nameAt-1, hello[nameAt-1:nameAt+5]))}, domain},
		{"large frame then a smaller one inside it that differs", []packetSpec{packet(0,
			cryptoSpec(0, hello[:n-1]), cryptoSpec(nameAt-1, other[nameAt-1:nameAt+5]), cryptoSpec(n-1, hello[n-1:]))}, outcome{class: conflict}},
		{"small frames then a large frame over them", []packetSpec{packet(0,
			append(splitInto(nameAt-8, hello[nameAt-8:nameAt+20], 3, 1, 5, 7), cryptoSpec(0, hello))...)}, domain},
		{"small frames then a large frame over them that differs", []packetSpec{packet(0,
			append(splitInto(nameAt-8, hello[nameAt-8:nameAt+20], 3, 1, 5, 7), cryptoSpec(0, other))...)}, outcome{class: conflict}},
		{"one-byte gap", []packetSpec{packet(0, cryptoSpec(0, hello[:nameAt]), cryptoSpec(nameAt+1, hello[nameAt+1:]))}, outcome{class: needMore}},
		{"one-byte gap filled by a later packet", []packetSpec{
			packet(0, cryptoSpec(0, hello[:nameAt]), cryptoSpec(nameAt+1, hello[nameAt+1:])),
			packet(1, cryptoSpec(nameAt, hello[nameAt:nameAt+1])),
		}, domain},
		{"large gap", []packetSpec{packet(0, cryptoSpec(0, hello[:10]), cryptoSpec(n-10, hello[n-10:]))}, outcome{class: needMore}},
		{"first frame after offset 0", []packetSpec{packet(0, cryptoSpec(1, hello[1:]))}, outcome{class: needMore}},
		{"offset 0 arriving in a later packet", []packetSpec{
			packet(0, cryptoSpec(5, hello[5:])),
			packet(1, cryptoSpec(0, hello[:5])),
		}, domain},
		{"data after the ClientHello in its frame", []packetSpec{packet(0, cryptoSpec(0, slices.Concat(hello, junk)))}, domain},
		{"data after the ClientHello in another frame", []packetSpec{packet(0, cryptoSpec(n, junk), cryptoSpec(0, hello))}, domain},
		{"conflicting data after the ClientHello before it completes", []packetSpec{packet(0,
			cryptoSpec(n, junk), cryptoSpec(n+3, []byte{1}), cryptoSpec(0, hello))}, outcome{class: conflict}},
		{"another handshake message after the ClientHello", []packetSpec{packet(0,
			cryptoSpec(0, slices.Concat(hello, []byte{2, 0, 0, 4, 3, 3, 0, 0})))}, domain},
		{"ClientHello ending at a frame boundary", []packetSpec{packet(0,
			cryptoSpec(0, hello[:n-7]), cryptoSpec(n-7, hello[n-7:]), cryptoSpec(n, junk))}, domain},
		{"ClientHello ending inside a frame", []packetSpec{packet(0,
			cryptoSpec(0, hello[:n-7]), cryptoSpec(n-7, slices.Concat(hello[n-7:], junk)))}, domain},
		{"ClientHello without its last byte", []packetSpec{packet(0, cryptoSpec(0, hello[:n-1]))}, outcome{class: needMore}},
		{"fragments on and around 64-byte words", []packetSpec{packet(0,
			splitInto(0, hello, 63, 1, 64, 65, 62, 2, 128, 127, 1, 8, 7, 9)...)}, domain},
		{"stream ending at the cap", []packetSpec{packet(0,
			cryptoSpec(streamCap-8, junk[:8]), cryptoSpec(0, hello))}, domain},
		{"stream ending one byte past the cap", []packetSpec{packet(0,
			cryptoSpec(streamCap-8, junk[:9]), cryptoSpec(0, hello))}, outcome{class: beyondCap}},
		{"empty frame at the cap", []packetSpec{packet(0, cryptoSpec(streamCap, nil), cryptoSpec(0, hello))}, domain},
		{"empty frame past the cap", []packetSpec{packet(0, cryptoSpec(streamCap+1, nil), cryptoSpec(0, hello))}, outcome{class: beyondCap}},
		{"offset at the largest accepted field", []packetSpec{packet(0, cryptoSpec(shortVarintMax, nil))}, outcome{class: beyondCap}},
		{"offset past the largest accepted field", []packetSpec{packet(0,
			invalidSpec(malformed, false, slices.Concat([]byte{0x06}, encodedOffset(shortVarintMax+1), []byte{1, 0})...),
			cryptoSpec(0, hello))}, outcome{class: malformed}},
		{"length past the end of the payload", []packetSpec{packet(0,
			cryptoSpec(0, hello[:n-4]), invalidSpec(malformed, true, 0x06, 0x00, 0x08, 1, 2, 3))}, outcome{class: malformed}},
		{"frame type at the end of the payload", []packetSpec{packet(0,
			cryptoSpec(0, hello[:n-4]), invalidSpec(malformed, true, 0x06))}, outcome{class: malformed}},
		{"truncated offset at the end of the payload", []packetSpec{packet(0,
			cryptoSpec(0, hello[:n-4]), invalidSpec(malformed, true, 0x06, 0x40))}, outcome{class: malformed}},
		{"identical retransmission in a later packet", []packetSpec{
			packet(0, cryptoSpec(0, hello[:n/2])),
			packet(1, cryptoSpec(0, hello)),
		}, domain},
		{"differing retransmission before the ClientHello completes", []packetSpec{
			packet(0, cryptoSpec(0, hello[:n-1])),
			packet(1, cryptoSpec(0, other)),
		}, outcome{class: conflict}},
		{"differing retransmission after the ClientHello completed", []packetSpec{
			packet(0, cryptoSpec(0, hello)),
			packet(1, cryptoSpec(0, other)),
		}, domain},
		{"stream starting with another handshake message", []packetSpec{packet(0,
			cryptoSpec(0, []byte{2, 0, 0, 4, 3, 3, 0, 0}))}, outcome{class: notClientHello}},
		{"ClientHello length past the cap", []packetSpec{packet(0, cryptoSpec(0, pastCapHello[:200]))}, outcome{class: notClientHello}},
		{"ClientHello as long as the cap", spreadOver(evenly(0, capHello, 4)), domain},
		{"ClientHello as long as the cap without its last byte", spreadOver(evenly(0, capHello[:streamCap-1], 4)), outcome{class: needMore}},
		{"packets of another connection in between", []packetSpec{
			packet(0, cryptoSpec(0, hello[:n-10])),
			{pn: 1, foreign: true, frames: []frameSpec{cryptoSpec(0, other)}},
			packet(2, cryptoSpec(n-10, hello[n-10:])),
		}, domain},
		{"frame type not allowed in Initial packets", []packetSpec{packet(0,
			invalidSpec(notInInitial, false, 0x07), cryptoSpec(0, hello))}, outcome{class: notInInitial}},
		{"CRYPTO frame type in two bytes", []packetSpec{packet(0,
			invalidSpec(notInInitial, false, slices.Concat([]byte{0x40, 0x06, 0x00}, quicvarint.Append(nil, uint64(n)), hello)...))}, outcome{class: notInInitial}},
		{"ACK, PING, PADDING and CONNECTION_CLOSE around the fragments", []packetSpec{packet(0,
			ack, rawSpec(0x01), cryptoSpec(n/2, hello[n/2:]), rawSpec(0, 0, 0), connectionClose, cryptoSpec(0, hello[:n/2]), rawSpec(0, 0))}, domain},
		{"empty CRYPTO frames anywhere", []packetSpec{packet(0,
			cryptoSpec(0, nil), cryptoSpec(n, nil), cryptoSpec(0, hello), cryptoSpec(streamCap, nil))}, domain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sniffAndCompare(t, tt.packets, &tt.want)
		})
	}
}

// randomFlow builds the Initial packets of a client whose CRYPTO stream starts
// with hello, cut into fragments that are reordered, repeated, overlapped,
// changed, left out, extended and mixed with other frames and packets.
// alternate is hello with another server name of the same length.
func randomFlow(r *rand.Rand, hello, alternate []byte) []packetSpec {
	stream := bytes.Clone(hello)
	randomBytes := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.IntN(256))
		}
		return b
	}
	switch r.IntN(20) {
	case 0, 1, 2, 3, 4, 5: // data after the ClientHello
		stream = append(stream, randomBytes(1+r.IntN(300))...)
	case 6: // up to and around the stream cap
		stream = append(stream, randomBytes(streamCap-len(stream)-3+r.IntN(5))...)
	}
	alternateStream := bytes.Clone(stream)
	copy(alternateStream, alternate)
	randomRange := func(maxLen int) (int, int) {
		from := r.IntN(len(stream))
		return from, from + 1 + r.IntN(min(maxLen, len(stream)-from))
	}

	// A hole in the stream, often in the server name, filled later or never.
	holeFrom, holeTo := 0, 0
	if r.IntN(4) == 0 {
		switch r.IntN(4) {
		case 0: // in the server name
			first := 0 // where the server names start to differ
			for hello[first] == alternate[first] {
				first++
			}
			holeFrom = first - 1 + r.IntN(3)
			holeTo = holeFrom + 1 + r.IntN(5)
		case 1: // the last bytes of the ClientHello
			holeTo = len(hello) - r.IntN(2)
			holeFrom = holeTo - 1 - r.IntN(3)
		case 2: // the handshake header
			holeFrom = r.IntN(4)
			holeTo = holeFrom + 1 + r.IntN(2)
		default:
			holeFrom, holeTo = randomRange(64)
		}
	}
	var frames, late []frameSpec
	maxFragment := []int{1, 3, 16, 64, 700, len(stream)}[r.IntN(6)]
	for at := 0; at < len(stream); {
		if at == holeFrom && holeTo > holeFrom {
			at = holeTo
			continue
		}
		size := 1 + r.IntN(maxFragment)
		if r.IntN(4) == 0 { // end on, just before or just after a word boundary
			size = max(1, (at+size)/64*64+r.IntN(3)-1-at)
		}
		// A frame must fit in a packet with its 9-byte header.
		to := min(at+size, len(stream), at+maxPacketPayload-9)
		if at < holeFrom && to > holeFrom {
			to = holeFrom
		}
		frames = append(frames, cryptoSpec(at, stream[at:to]))
		at = to
	}
	if holeTo > holeFrom {
		switch r.IntN(3) {
		case 1: // the bytes that were left out
			late = append(late, cryptoSpec(holeFrom, stream[holeFrom:holeTo]))
		case 2: // other bytes: the alternate server name, maybe changed
			data := bytes.Clone(alternateStream[holeFrom:holeTo])
			if r.IntN(3) == 0 {
				data[r.IntN(len(data))] ^= 1 << r.IntN(8)
			}
			late = append(late, cryptoSpec(holeFrom, data))
		}
	}
	for range r.IntN(5) { // repeats with the same bytes
		from, to := randomRange(800)
		frames = append(frames, cryptoSpec(from, stream[from:to]))
	}
	if r.IntN(4) == 0 { // a repeat with different bytes
		from, to := randomRange(400)
		data := bytes.Clone(alternateStream[from:to])
		if r.IntN(2) == 0 || bytes.Equal(data, stream[from:to]) {
			data[r.IntN(len(data))] ^= 1 << r.IntN(8)
		}
		frames = append(frames, cryptoSpec(from, data))
	}
	for range r.IntN(3) { // empty CRYPTO frames
		frames = append(frames, cryptoSpec(r.IntN(len(stream)+2), nil))
	}
	for range r.IntN(4) { // frames other than CRYPTO
		switch r.IntN(4) {
		case 0:
			frames = append(frames, rawSpec(make([]byte, 1+r.IntN(20))...))
		case 1:
			frames = append(frames, rawSpec(0x01))
		case 2:
			ranges := r.IntN(3)
			f := []byte{0x02 | byte(r.IntN(2)), byte(r.IntN(64)), byte(r.IntN(64)), byte(ranges), byte(r.IntN(64))}
			for range 2 * ranges {
				f = append(f, byte(r.IntN(64)))
			}
			if f[0] == 0x03 {
				f = append(f, 1, 2, 3)
			}
			frames = append(frames, rawSpec(f...))
		case 3:
			frames = append(frames, rawSpec(0x1c, byte(r.IntN(64)), 0x06, 0x03, 'b', 'y', 'e'))
		}
	}
	switch r.IntN(3) {
	case 1:
		slices.Reverse(frames)
	case 2:
		r.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
	}
	if r.IntN(25) == 0 { // a frame the sniffer must reject
		bad := []frameSpec{
			invalidSpec(notInInitial, false, 0x07),
			invalidSpec(notInInitial, false, 0x1d, 0, 0, 0),
			invalidSpec(malformed, false, 0x06, 0x80, 0x01, 0x00, 0x00, 0x00),
			invalidSpec(malformed, true, 0x06, 0x00, 0x44, 0x00, 1),
			invalidSpec(malformed, true, 0x02, 0x01),
			invalidSpec(malformed, true, 0x1c, 0, 0, 9, 'x'),
		}[r.IntN(6)]
		frames = slices.Insert(frames, r.IntN(len(frames)+1), bad)
	}

	var packets []packetSpec
	var current []frameSpec
	size := 0
	flush := func() {
		if len(current) > 0 {
			packets = append(packets, packet(uint32(len(packets)), current...))
			current, size = nil, 0
		}
	}
	cuts := 1 + r.IntN(4)
	for i, f := range frames {
		encoded := len(encodePayload([]frameSpec{f}))
		if size+encoded > maxPacketPayload || i > 0 && r.IntN(len(frames)) < cuts {
			flush()
		}
		current = append(current, f)
		size += encoded
		if f.last {
			flush()
		}
	}
	flush()
	if len(late) > 0 {
		packets = append(packets, packet(uint32(len(packets)), late...))
	}
	if r.IntN(4) == 0 { // packet numbers out of order
		pns := r.Perm(len(packets) + 3)
		for i := range packets {
			packets[i].pn = uint32(pns[i])
		}
	}
	if len(packets) > 1 && r.IntN(8) == 0 { // a packet number used again
		i := 1 + r.IntN(len(packets)-1)
		packets[i].pn = packets[r.IntN(i)].pn
	}
	if r.IntN(8) == 0 { // a packet of another connection, never the first
		foreign := packetSpec{pn: uint32(r.IntN(9)), foreign: true, frames: []frameSpec{cryptoSpec(0, alternate)}}
		packets = slices.Insert(packets, 1+r.IntN(len(packets)), foreign)
	}
	return packets
}

// referenceTestHellos returns a ClientHello and the same ClientHello with a
// server name of the same length, so that differing repeats can change the
// server name or mix the two.
func referenceTestHellos(tb testing.TB) ([]byte, []byte) {
	tb.Helper()
	const name, alternateName = "aaaa.sniff.test", "bbbb.sniff.test"
	hello := quicTLSClientHello(tb, name)
	return hello, bytes.Replace(hello, []byte(name), []byte(alternateName), 1)
}

// Random flows built from every adversarial pattern above must yield exactly
// what the model yields: the same server name, or the same class of error.
func TestSniffQUICMatchesReferenceReassembly(t *testing.T) {
	hello, alternate := referenceTestHellos(t)
	r := rand.New(rand.NewPCG(0xadd, 0xc0de))
	outcomes := map[outcome]int{}
	for round := range 3000 {
		packets := randomFlow(r, hello, alternate)
		t.Run("", func(t *testing.T) {
			outcomes[sniffAndCompare(t, packets, nil)]++
		})
		if t.Failed() {
			t.Fatalf("round %d failed", round)
		}
	}
	t.Logf("outcomes: %v", outcomes)
}

// FuzzSniffQUICFlows feeds the random flow generator fuzzed seeds.
func FuzzSniffQUICFlows(f *testing.F) {
	hello, alternate := referenceTestHellos(f)
	for seed := range uint64(8) {
		f.Add(seed, seed*31)
	}
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		sniffAndCompare(t, randomFlow(rand.New(rand.NewPCG(seed1, seed2)), hello, alternate), nil)
	})
}

// decodeFuzzedPackets reads Initial packets from fuzz input: for each, a
// packet number byte, a byte whose low bit makes the packet foreign, a 2-byte
// payload length and the decrypted payload, whose frames are arbitrary bytes.
func decodeFuzzedPackets(input []byte) ([]packetSpec, [][]byte) {
	var packets []packetSpec
	var payloads [][]byte
	for len(input) >= 4 && len(packets) < 6 {
		length := min(int(input[2])<<8|int(input[3]), len(input)-4, maxPacketPayload)
		payload := input[4 : 4+length]
		p := packetSpec{pn: uint32(input[0]), foreign: input[1]&1 == 1 && len(packets) > 0}
		p.frames = []frameSpec{rawSpec(payload...)}
		packets = append(packets, p)
		payloads = append(payloads, payload)
		input = input[4+length:]
	}
	return packets, payloads
}

// encodeFuzzedPackets is the inverse of decodeFuzzedPackets, for seeds.
func encodeFuzzedPackets(payloads ...[]byte) []byte {
	var input []byte
	for i, payload := range payloads {
		input = append(input, byte(i), 0, byte(len(payload)>>8), byte(len(payload)))
		input = append(input, payload...)
	}
	return input
}

// Whatever frames a client puts in its Initial packets, SniffQUIC must not
// panic or modify them, and must yield what the model yields from frames it
// parses on its own.
func FuzzSniffQUICFrames(f *testing.F) {
	hello, _ := referenceTestHellos(f)
	n := len(hello)
	f.Add(encodeFuzzedPackets(appendCryptoFrames(nil, cryptoFrame{0, hello})))
	f.Add(encodeFuzzedPackets(
		appendCryptoFrames([]byte{0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, cryptoFrame{n / 2, hello[n/2:]}),
		appendCryptoFrames([]byte{0x01, 0x00}, cryptoFrame{0, hello[:n/2+3]}),
	))
	f.Add(encodeFuzzedPackets(appendCryptoFrames(nil, cryptoFrame{0, hello[:n-1]}, cryptoFrame{n - 2, []byte{0xff, 0xff}})))
	f.Add(encodeFuzzedPackets(appendCryptoFrames([]byte{0x1c, 0x00, 0x00, 0x00}, cryptoFrame{streamCap - 3, []byte{1, 2, 3}}, cryptoFrame{0, hello})))
	f.Fuzz(func(t *testing.T, input []byte) {
		packets, payloads := decodeFuzzedPackets(input)
		if len(packets) == 0 {
			return
		}
		flow := sealFlow(t, packets)
		sent := bytes.Clone(flow)
		got := sniffOutcome(quic.SniffQUIC(flow))
		if !bytes.Equal(flow, sent) {
			t.Fatal("SniffQUIC modified the flow")
		}
		parsed := make([]packetSpec, len(packets))
		for i, payload := range payloads {
			parsed[i] = packetSpec{pn: packets[i].pn, foreign: packets[i].foreign, frames: parseReferenceFrames(payload)}
		}
		if want := referenceReassembly(parsed); got != want {
			t.Fatalf("SniffQUIC yields %v, the model %v\n%s", got, want, describeFlow(parsed))
		}
	})
}

// A receiver recovers a packet number sent in fewer bytes from the largest
// one it has received (RFC 9000, Appendix A). Read as is, packet 256 sent in
// one byte looks like packet 0 and does not decrypt, so the sniffer missed the
// server name a server reads in it and routed by the one a later packet
// carries.
func TestSniffQUICDecodesTruncatedPacketNumbers(t *testing.T) {
	const name, laterName = "trunc.sniff.test", "later.sniff.test"
	hello := quicTLSClientHello(t, name)
	later := bytes.Replace(hello, []byte(name), []byte(laterName), 1)
	from := bytes.Index(hello, []byte(name))
	to := from + len(name)
	flow := sealInitialPacket(t, reassemblyDestConnID, 0, 4, appendCryptoFrames(nil, cryptoFrame{0, hello[:from]}, cryptoFrame{to, hello[to:]}))
	for pn := uint64(1); pn < 256; pn++ {
		flow = append(flow, sealInitialPacket(t, reassemblyDestConnID, pn, 4, []byte{0x01, 0, 0, 0})...)
	}
	flow = append(flow, sealInitialPacket(t, reassemblyDestConnID, 256, 1, appendCryptoFrames(nil, cryptoFrame{from, hello[from:to]}))...)
	flow = append(flow, sealInitialPacket(t, reassemblyDestConnID, 257, 4, appendCryptoFrames(nil, cryptoFrame{from, later[from:to]}))...)
	header, err := quic.SniffQUIC(flow)
	if err != nil || header.Domain() != name {
		t.Fatalf("SniffQUIC() = (%q, %v), want %q", sniffedDomain(header), err, name)
	}
}

// A receiver discards a packet whose number it has processed before (RFC
// 9000, Section 12.3): the first copy counts. Reading every copy let a client
// complete its ClientHello with bytes no server reads. A datagram the network
// delivers twice must still be sniffed.
func TestSniffQUICDiscardsRepeatedPacketNumbers(t *testing.T) {
	const name, repeatedName = "first.sniff.test", "again.sniff.test"
	hello := quicTLSClientHello(t, name)
	repeated := bytes.Replace(hello, []byte(name), []byte(repeatedName), 1)
	from := bytes.Index(hello, []byte(name))
	to := from + len(name)
	tests := []struct {
		name    string
		packets []packetSpec
	}{
		{"repeat carrying other bytes", []packetSpec{
			packet(0, cryptoSpec(0, hello[:from]), cryptoSpec(to, hello[to:])),
			packet(0, cryptoSpec(from, repeated[from:to])),
			packet(1, cryptoSpec(from, hello[from:to])),
		}},
		{"datagram delivered twice", []packetSpec{
			packet(0, cryptoSpec(0, hello[:from])),
			packet(0, cryptoSpec(0, hello[:from])),
			packet(1, cryptoSpec(from, hello[from:])),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := outcome{domain: name}
			sniffAndCompare(t, tt.packets, &want)
		})
	}
}

// zeroRTTPacket returns a QUIC v1 0-RTT packet of the connection with
// destConnID: a long header packet that is not an Initial, with junk where
// its protected payload goes.
func zeroRTTPacket(destConnID []byte) []byte {
	packet := []byte{0xd3, 0, 0, 0, 1, byte(len(destConnID))}
	packet = append(packet, destConnID...)
	packet = append(packet, 0) // no Source Connection ID
	packet = quicvarint.AppendWithLen(packet, 40, 2)
	return append(packet, bytes.Repeat([]byte{0x3c}, 40)...)
}

// undecryptableInitial returns bytes that parse as an Initial packet of the
// connection with destConnID but fail to decrypt, as a datagram tail can.
func undecryptableInitial(destConnID []byte) []byte {
	packet := []byte{0xc3, 0, 0, 0, 1, byte(len(destConnID))}
	packet = append(packet, destConnID...)
	packet = append(packet, 0, 0) // no Source Connection ID, no token
	packet = quicvarint.AppendWithLen(packet, 48, 2)
	return append(packet, bytes.Repeat([]byte{0xa7}, 48)...)
}

// The behavior b13d0be6 introduced, which the packet number handling must
// keep. The dispatcher hands the sniffer a flow's datagrams concatenated:
//
//   - B1: the connection sniffed is the one of the first Initial packet;
//     Initial packets of other connections add nothing, wherever they are.
//   - B2: bytes after the last packet of a datagram, zero or not, do not end
//     sniffing; it resumes at the next Initial packet of the connection.
//   - B3: that search only matches the connection's version and Destination
//     Connection ID behind an Initial packet type, and always moves on.
//   - B4: packets coalesced in a datagram are read in order, long header
//     packets other than Initial skipped.
//   - B5: a later packet of the connection that does not decrypt is skipped.
//
// And what the packet number handling adds:
//
//   - F1: packet numbers belong to the connection sniffed; another
//     connection's packets, and packets that do not decrypt, leave them be.
//   - F2: a number sent with enough bytes decodes to itself, in any order.
//   - F3: a repeated packet number is skipped; an identical copy changes
//     nothing.
//
// Each flow is checked datagram by datagram: more data is needed until the
// last one completes the ClientHello.
func TestSniffQUICFollowsItsConnectionAcrossDatagrams(t *testing.T) {
	for _, tt := range connectionFollowingFlows(t) {
		t.Run(tt.name, func(t *testing.T) {
			assertSniffDatagrams(t, tt.datagrams, tt.want)
		})
	}
}

// connectionFlow is a flow of datagrams and the server name it yields.
type connectionFlow struct {
	name      string
	datagrams [][]byte
	want      string
}

// connectionFollowingFlows returns the flows of
// TestSniffQUICFollowsItsConnectionAcrossDatagrams.
func connectionFollowingFlows(t *testing.T) []connectionFlow {
	t.Helper()
	const name, otherName = "keep.sniff.test", "else.sniff.test"
	hello := quicTLSClientHello(t, name)
	other := quicTLSClientHello(t, otherName)
	n := len(hello)
	parts := [][2]int{{0, n / 3}, {n / 3, 2 * n / 3}, {2 * n / 3, n}}
	ours := func(pn uint64, pnLength int, part int) []byte {
		from, to := parts[part][0], parts[part][1]
		return sealInitialPacket(t, reassemblyDestConnID, pn, pnLength, appendCryptoFrames(nil, cryptoFrame{from, hello[from:to]}))
	}
	theirs := func(pn uint64, pnLength int) []byte {
		return sealInitialPacket(t, foreignDestConnID, pn, pnLength, appendCryptoFrames(nil, cryptoFrame{0, other}))
	}
	with := func(datagram []byte, tail ...[]byte) []byte {
		return slices.Concat(append([][]byte{datagram}, tail...)...)
	}
	zeros := make([]byte, 40)
	junk := bytes.Repeat([]byte{0x5a}, 37)
	notInitial := zeroRTTPacket(reassemblyDestConnID)
	undecryptable := undecryptableInitial(reassemblyDestConnID)

	return []connectionFlow{
		// B1, F1
		{"other connection reusing our packet numbers before ours", [][]byte{
			ours(0, 4, 0), theirs(0, 4), theirs(1, 4), ours(1, 4, 1), theirs(2, 4), ours(2, 4, 2)}, name},
		{"other connection with one-byte packet numbers between ours", [][]byte{
			ours(0, 1, 0), theirs(1, 1), ours(1, 1, 1), theirs(2, 1), ours(2, 1, 2)}, name},
		{"other connection first", [][]byte{theirs(0, 4)}, otherName},
		// B2, B3, B5, F1
		{"zero and non-zero tails", [][]byte{
			with(ours(0, 4, 0), zeros), with(ours(1, 4, 1), junk), ours(2, 4, 2)}, name},
		{"tail with the signature behind another packet type", [][]byte{
			with(ours(0, 4, 0), notInitial[:20], junk), ours(1, 4, 1), ours(2, 4, 2)}, name},
		{"tail parsing as a packet of the connection that does not decrypt", [][]byte{
			with(ours(0, 4, 0), undecryptable), with(ours(1, 4, 1), undecryptable), ours(2, 4, 2)}, name},
		// F1: the packets that do not decrypt leave the largest packet number,
		// which 301 and 302 in one byte decode from, at 300.
		{"tail that does not decrypt before one-byte packet numbers", [][]byte{
			with(ours(300, 2, 0), undecryptable), with(ours(301, 1, 1), undecryptable), ours(302, 1, 2)}, name},
		// B4
		{"0-RTT packets coalesced with Initial packets", [][]byte{
			with(ours(0, 4, 0), notInitial, ours(1, 4, 1)), with(notInitial, ours(2, 4, 2))}, name},
		// F2
		{"packet numbers out of order", [][]byte{ours(2, 4, 2), ours(0, 4, 0), ours(1, 4, 1)}, name},
		{"one-byte packet numbers out of order", [][]byte{ours(2, 1, 2), ours(0, 1, 0), ours(1, 1, 1)}, name},
		{"large first packet number, as ngtcp2 picks", [][]byte{
			ours(1360156657, 4, 0), with(ours(1360156658, 4, 1), junk), ours(1360156659, 4, 2)}, name},
		// F3, B2
		{"datagram repeated after its tail", [][]byte{
			with(ours(0, 4, 0), junk), with(ours(0, 4, 0), junk), ours(1, 4, 1), ours(2, 4, 2)}, name},
	}
}
