package quic_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
)

// shortDatagram is the outcome of a flow with an Initial packet of the
// connection in a datagram below 1200 bytes after the connection started.
const shortDatagram = "Initial packet in a short datagram"

// sniffDatagramsOutcome classifies what quic.SniffQUICDatagrams returned.
func sniffDatagramsOutcome(header *quic.SniffHeader, err error) outcome {
	if err != nil && strings.Contains(err.Error(), "datagram below 1200 bytes") {
		return outcome{class: shortDatagram}
	}
	return sniffOutcome(header, err)
}

// padTo1200 returns datagram with zeros after its packets up to 1200 bytes,
// as Firefox pads its datagrams.
func padTo1200(datagram []byte) []byte {
	return padTo(datagram, 1200)
}

// padTo returns datagram with zeros after its packets up to size bytes.
func padTo(datagram []byte, size int) []byte {
	return append(bytes.Clone(datagram), make([]byte, max(0, size-len(datagram)))...)
}

// assertSniffSeparateDatagrams checks SniffQUICDatagrams datagram by datagram:
// more data is needed until the last datagram yields domain, and no datagram
// is written to.
func assertSniffSeparateDatagrams(t *testing.T, datagrams [][]byte, domain string) {
	t.Helper()
	for i := 1; i <= len(datagrams); i++ {
		received := make([][]byte, i)
		for j := range received {
			received[j] = bytes.Clone(datagrams[j])
		}
		header, err := quic.SniffQUICDatagrams(received)
		for j := range received {
			if !bytes.Equal(received[j], datagrams[j]) {
				t.Fatalf("SniffQUICDatagrams modified datagram %d", j)
			}
		}
		if i < len(datagrams) {
			if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
				t.Fatalf("after %d of %d datagrams: SniffQUICDatagrams() = (%q, %v), want more data", i, len(datagrams), sniffedDomain(header), err)
			}
			continue
		}
		if err != nil || header.Domain() != domain {
			t.Fatalf("after %d datagrams: SniffQUICDatagrams() = (%q, %v), want %q", i, sniffedDomain(header), err, domain)
		}
	}
}

// With its datagrams kept apart, the sniffer keeps what b13d0be6 brought:
// the flows of TestSniffQUICFollowsItsConnectionAcrossDatagrams, each datagram
// padded to 1200 bytes, yield the same server names.
func TestSniffQUICDatagramsFollowItsConnection(t *testing.T) {
	for _, flow := range connectionFollowingFlows(t) {
		t.Run(flow.name, func(t *testing.T) {
			datagrams := make([][]byte, len(flow.datagrams))
			for i, datagram := range flow.datagrams {
				datagrams[i] = padTo1200(datagram)
			}
			assertSniffSeparateDatagrams(t, datagrams, flow.want)
		})
	}
}

// smallQUICClientHello is quicTLSClientHello offering X25519 alone, so that
// the ClientHello fits in a datagram below 1200 bytes.
func smallQUICClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	conn := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName:       serverName,
		MinVersion:       tls.VersionTLS13,
		NextProtos:       []string{"h3"},
		CurvePreferences: []tls.CurveID{tls.X25519},
	}})
	conn.SetTransportParameters(nil)
	if err := conn.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for {
		event := conn.NextEvent()
		switch {
		case event.Kind == tls.QUICNoEvent:
			t.Fatal("the QUIC client sent no ClientHello")
		case event.Kind == tls.QUICWriteData && event.Level == tls.QUICEncryptionLevelInitial:
			return bytes.Clone(event.Data)
		}
	}
}

// Every client of the corpus sends datagrams of at least 1200 bytes, so kept
// apart they yield, datagram by datagram, what SniffQUIC reads from them
// concatenated.
func TestSniffQUICDatagramsCorpus(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.bin"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no corpus: %v", err)
	}
	flows := map[string][][]byte{}
	for _, path := range paths {
		datagram, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Base(path)
		prefix := base[:strings.LastIndex(base, "-")]
		flows[prefix] = append(flows[prefix], datagram)
	}
	for prefix, datagrams := range flows {
		t.Run(prefix, func(t *testing.T) {
			for i := 1; i <= len(datagrams); i++ {
				want := sniffOutcome(quic.SniffQUIC(bytes.Join(datagrams[:i], nil)))
				if got := sniffDatagramsOutcome(quic.SniffQUICDatagrams(datagrams[:i])); got != want {
					t.Fatalf("after %d datagrams: SniffQUICDatagrams() yields %v, SniffQUIC %v", i, got, want)
				}
			}
			if got := sniffOutcome(quic.SniffQUIC(bytes.Join(datagrams, nil))); got.class != "" {
				t.Fatalf("the whole flow yields %v, want a server name", got)
			}
		})
	}
}

// What a QUIC server does with each datagram on its own decides what the
// sniffer reads; with the datagrams concatenated, it read what servers
// discard.
func TestSniffQUICDatagramsFollowServerReceiveRules(t *testing.T) {
	const name, otherName = "rule.sniff.test", "else.sniff.test"
	hello := quicTLSClientHello(t, name)
	other := quicTLSClientHello(t, otherName)
	n := len(hello)
	parts := [][2]int{{0, n / 3}, {n / 3, 2 * n / 3}, {2 * n / 3, n}}
	ours := func(pn uint64, part int) []byte {
		from, to := parts[part][0], parts[part][1]
		return sealInitialPacket(t, reassemblyDestConnID, pn, 4, appendCryptoFrames(nil, cryptoFrame{from, hello[from:to]}))
	}
	// paddedOurs is ours with PADDING frames up to a 1200-byte packet.
	paddedOurs := func(pn uint64, part int) []byte {
		from, to := parts[part][0], parts[part][1]
		payload := appendCryptoFrames(nil, cryptoFrame{from, hello[from:to]})
		return sealInitialPacket(t, reassemblyDestConnID, pn, 4, append(payload, make([]byte, 1200-len(payload)-40)...))
	}
	whole := sealInitialPacket(t, reassemblyDestConnID, 0, 4, appendCryptoFrames(nil, cryptoFrame{0, smallQUICClientHello(t, "small.sniff.test")}))
	if len(whole) >= 1200 {
		t.Fatalf("the small ClientHello takes a %d-byte packet", len(whole))
	}
	theirs := sealInitialPacket(t, foreignDestConnID, 0, 4, appendCryptoFrames(nil, cryptoFrame{0, other}))
	junk := bytes.Repeat([]byte{0x5a}, 37)
	split := ours(1, 1)

	tests := []struct {
		name      string
		datagrams [][]byte
		want      outcome
	}{
		{"short first datagram with a whole ClientHello, then another connection", [][]byte{
			whole, padTo1200(theirs),
		}, outcome{domain: otherName}},
		{"first datagram of 1199 bytes", [][]byte{
			padTo(whole, 1199), padTo1200(theirs),
		}, outcome{domain: otherName}},
		{"first datagram of 1200 bytes", [][]byte{
			padTo(whole, 1200), padTo1200(theirs),
		}, outcome{domain: "small.sniff.test"}},
		{"short first datagram with the start of the ClientHello", [][]byte{
			ours(0, 0), padTo1200(slices.Concat(ours(1, 1), ours(2, 2))),
		}, outcome{class: needMore}},
		{"packet after junk in a datagram", [][]byte{
			padTo1200(slices.Concat(ours(0, 0), junk, ours(1, 1))), padTo1200(ours(2, 2)),
		}, outcome{class: needMore}},
		{"coalesced packet of another connection before one of ours", [][]byte{
			padTo1200(slices.Concat(ours(0, 0), theirs, ours(1, 1))), padTo1200(ours(2, 2)),
		}, outcome{class: needMore}},
		{"datagram whose first packet is another connection's", [][]byte{
			padTo1200(ours(0, 0)), padTo1200(slices.Concat(theirs, ours(1, 1))), padTo1200(ours(2, 2)),
		}, outcome{class: needMore}},
		{"packet running into the next datagram", [][]byte{
			slices.Concat(paddedOurs(0, 0), split[:40]), padTo1200(split[40:]), padTo1200(ours(2, 2)),
		}, outcome{class: needMore}},
		{"short datagram of the connection once started", [][]byte{
			padTo1200(ours(0, 0)), ours(1, 1), padTo1200(ours(2, 2)),
		}, outcome{class: shortDatagram}},
		{"short datagram repeating a packet number", [][]byte{
			padTo1200(ours(0, 0)), ours(0, 0), padTo1200(slices.Concat(ours(1, 1), ours(2, 2))),
		}, outcome{domain: name}},
		{"0-RTT packet coalesced between Initial packets", [][]byte{
			padTo1200(slices.Concat(ours(0, 0), zeroRTTPacket(reassemblyDestConnID), ours(1, 1))), padTo1200(ours(2, 2)),
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

// Whatever frames a client puts in its Initial packets, each sent in a
// datagram of its own padded to 1200 bytes, SniffQUICDatagrams must not panic
// or modify them, and must yield what the model yields.
func FuzzSniffQUICDatagrams(f *testing.F) {
	hello, _ := referenceTestHellos(f)
	n := len(hello)
	f.Add(encodeFuzzedPackets(appendCryptoFrames(nil, cryptoFrame{0, hello})))
	f.Add(encodeFuzzedPackets(
		appendCryptoFrames([]byte{0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, cryptoFrame{n / 2, hello[n/2:]}),
		appendCryptoFrames([]byte{0x01, 0x00}, cryptoFrame{0, hello[:n/2+3]}),
	))
	f.Fuzz(func(t *testing.T, input []byte) {
		packets, payloads := decodeFuzzedPackets(input)
		if len(packets) == 0 {
			return
		}
		datagrams := make([][]byte, len(packets))
		for i, p := range packets {
			datagrams[i] = padTo1200(sealFlow(t, []packetSpec{p}))
		}
		sent := make([][]byte, len(datagrams))
		for i := range datagrams {
			sent[i] = bytes.Clone(datagrams[i])
		}
		got := sniffDatagramsOutcome(quic.SniffQUICDatagrams(datagrams))
		for i := range datagrams {
			if !bytes.Equal(datagrams[i], sent[i]) {
				t.Fatal("SniffQUICDatagrams modified a datagram")
			}
		}
		parsed := make([]packetSpec, len(packets))
		for i, payload := range payloads {
			parsed[i] = packetSpec{pn: packets[i].pn, foreign: packets[i].foreign, frames: parseReferenceFrames(payload)}
		}
		if want := referenceReassembly(parsed); got != want {
			t.Fatalf("SniffQUICDatagrams yields %v, the model %v\n%s", got, want, describeFlow(parsed))
		}
	})
}

// Whatever bytes the datagrams of a UDP flow hold, SniffQUICDatagrams must
// neither panic nor write to them. The input is a sequence of datagrams, each
// after its 2-byte length.
func FuzzSniffQUICDatagramsRaw(f *testing.F) {
	for _, prefix := range []string{"quic-chrome153", "quic-firefox153esr", "quic-aioquic1.2"} {
		var input []byte
		for _, datagram := range readCorpus(f, prefix, 1) {
			input = append(input, byte(len(datagram)>>8), byte(len(datagram)))
			input = append(input, datagram...)
		}
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		var datagrams [][]byte
		for len(input) >= 2 {
			length := min(int(input[0])<<8|int(input[1]), len(input)-2)
			datagrams = append(datagrams, input[2:2+length])
			input = input[2+length:]
		}
		sent := make([][]byte, len(datagrams))
		for i := range datagrams {
			sent[i] = bytes.Clone(datagrams[i])
		}
		_, _ = quic.SniffQUICDatagrams(datagrams)
		for i := range datagrams {
			if !bytes.Equal(datagrams[i], sent[i]) {
				t.Fatal("SniffQUICDatagrams modified a datagram")
			}
		}
	})
}
