package dispatcher

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// withoutPadding returns a captured datagram without the zero padding that
// follows its last packet: a datagram below the 1200 bytes RFC 9000, Section
// 14.1 requires of one that carries an Initial packet.
func withoutPadding(t *testing.T, datagram []byte, padding int) []byte {
	t.Helper()
	short := datagram[:len(datagram)-padding]
	if len(short) >= 1200 || !bytes.Equal(datagram[len(short):], make([]byte, padding)) {
		t.Fatalf("the datagram does not end with %d bytes of padding leaving it below 1200 bytes", padding)
	}
	return bytes.Clone(short)
}

// newTestCachedReader returns a cached reader of link that releases what it
// still caches when the test ends.
func newTestCachedReader(t *testing.T, link buf.TimeoutReader) *cachedReader {
	t.Helper()
	reader := newCachedReader(link)
	t.Cleanup(func() { buf.ReleaseMulti(reader.readInternal()) })
	return reader
}

// A QUIC server reads each datagram on its own, and discards an Initial
// packet in a datagram below 1200 bytes, which thus starts no connection. The
// dispatcher handed the QUIC sniffer the flow's datagrams as one byte stream,
// so it followed the connection of the first Initial packet even in such a
// datagram, and routed by a server name no server reads.
func TestSniffQUICIgnoresInitialDatagramsBelow1200Bytes(t *testing.T) {
	// aioquic and Firefox pad their first datagram after its packet, so
	// taking that padding off leaves whole packets in a short datagram.
	aioquic := readQUICCorpus(t, "quic-aioquic1.2", 1)[0]
	firefox := readQUICCorpus(t, "quic-firefox153esr", 2)
	ngtcp2 := readQUICCorpus(t, "quic-ngtcp2-1.11", 1)[0]
	tests := []struct {
		name      string
		datagrams [][]byte
		domain    string // empty when a server has no complete ClientHello
	}{
		{"short datagram with a whole ClientHello, then another connection", [][]byte{
			withoutPadding(t, aioquic, 673), ngtcp2,
		}, "ngtcp2.sniff.test"},
		{"short datagram with the start of the ClientHello, then its end", [][]byte{
			withoutPadding(t, firefox[0], 259), firefox[1],
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newTestCachedReader(t, &datagramReader{datagrams: tt.datagrams})
			ctx := snifferContext()
			result, err := sniff(ctx, reader, false, net.Network_UDP, newSniffer(ctx))
			switch {
			case tt.domain == "" && err == nil:
				t.Fatalf("sniff() = %s %q, want no server name", result.Protocol(), result.Domain())
			case tt.domain != "" && err != nil:
				t.Fatalf("sniff() error = %v, want quic %q", err, tt.domain)
			case tt.domain != "" && (result.Protocol() != "quic" || result.Domain() != tt.domain):
				t.Fatalf("sniff() = %s %q, want quic %q", result.Protocol(), result.Domain(), tt.domain)
			}
		})
	}
}

// bufferReader yields all its buffers in one read, as an inbound whose reader
// returns several at once does, and times out afterwards.
type bufferReader struct {
	buffers [][]byte
}

func (r *bufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.ReadMultiBufferTimeout(0)
}

func (r *bufferReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	if len(r.buffers) == 0 {
		return nil, buf.ErrReadTimeout
	}
	var mb buf.MultiBuffer
	for _, b := range r.buffers {
		mb = append(mb, buf.FromBytes(bytes.Clone(b)))
	}
	r.buffers = nil
	return mb, nil
}

// A UDP link carries one datagram per buffer: the outbound sends each buffer
// it is handed as a datagram of its own (TestPacketWriterSendsEachBufferAsADatagram
// in proxy/freedom). The datagrams the sniffer reads are thus the cached
// buffers, as the destination receives them, even where an inbound merged or
// split the client's datagrams. VMess merges a datagram of 8177 bytes or more
// into the free space of the buffer before it (common/crypto/auth.go): a
// client's datagrams of 527 and 8192 bytes reach the dispatcher as buffers of
// 8192 and 527 bytes, the first starting with the whole short datagram. The
// destination receives a datagram of 8192 bytes that starts with that Initial
// packet, and reads its ClientHello, which the sniffer names too.
func TestSniffQUICReadsTheDatagramsTheOutboundSends(t *testing.T) {
	aioquic := withoutPadding(t, readQUICCorpus(t, "quic-aioquic1.2", 1)[0], 673)
	ngtcp2 := readQUICCorpus(t, "quic-ngtcp2-1.11", 1)[0]
	merged := slices.Concat(aioquic, ngtcp2, make([]byte, 8192-len(ngtcp2)))
	buffers := [][]byte{merged[:8192], merged[8192:]}
	reader := newTestCachedReader(t, &bufferReader{buffers: buffers})
	ctx := snifferContext()
	result, err := sniff(ctx, reader, false, net.Network_UDP, newSniffer(ctx))
	if err != nil || result.Protocol() != "quic" || result.Domain() != "aioquic.sniff.test" {
		t.Fatalf("sniff() = (%v, %v), want quic aioquic.sniff.test", result, err)
	}
	lent := reader.Datagrams()
	forwarded, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(forwarded)
	if len(lent) != len(buffers) || len(forwarded) != len(buffers) {
		t.Fatalf("lent %d and forwarded %d datagrams, want the %d buffers", len(lent), len(forwarded), len(buffers))
	}
	for i := range buffers {
		if !bytes.Equal(lent[i], buffers[i]) || !bytes.Equal(forwarded[i].Bytes(), buffers[i]) {
			t.Fatalf("datagram %d is lent or forwarded other than its buffer of %d bytes", i, len(buffers[i]))
		}
	}
}

// With FakeDNS, a flow to a fake address the engine has no domain for is
// sniffed by the other sniffers through a wrapper, which must hand the QUIC
// sniffer the datagrams apart as well.
func TestFakeDNSThenOthersSniffsQUICDatagramsApart(t *testing.T) {
	inRange := protocolSnifferWithMetadata{
		protocolSniffer: func(ctx context.Context, _ []byte) (SniffResult, error) {
			yes := true
			ctx.Value(ipAddressInRange).(*ipAddressInRangeOpt).addressInRange = &yes
			return nil, common.ErrNoClue
		},
		metadataSniffer: true,
	}
	wrapper, err := newFakeDNSThenOthers(context.Background(), inRange, defaultProtocolSniffers[:])
	if err != nil {
		t.Fatal(err)
	}
	aioquic := readQUICCorpus(t, "quic-aioquic1.2", 1)[0]
	datagrams := [][]byte{withoutPadding(t, aioquic, 673), readQUICCorpus(t, "quic-ngtcp2-1.11", 1)[0]}
	result, err := wrapper.datagramSniffer(context.Background(), bytes.Join(datagrams, nil), datagrams)
	if err != nil || result.Domain() != "ngtcp2.sniff.test" {
		domain := ""
		if result != nil {
			domain = result.Domain()
		}
		t.Fatalf("sniffed %q (%v), want ngtcp2.sniff.test", domain, err)
	}
}

// The dispatcher hands the QUIC sniffer each datagram whole and apart, however
// long, longer than quic-go reads one included: Chrome's first two datagrams
// padded to 1498 bytes, or their packets coalesced in one datagram.
func TestSniffQUICKeepsLongDatagramsWhole(t *testing.T) {
	chrome := readQUICCorpus(t, "quic-chrome153", 2)
	padded := func(datagram []byte, size int) []byte {
		return append(bytes.Clone(datagram), make([]byte, size-len(datagram))...)
	}
	tests := []struct {
		name      string
		datagrams [][]byte
	}{
		{"two datagrams padded to 1498 bytes", [][]byte{padded(chrome[0], 1498), padded(chrome[1], 1498)}},
		{"one datagram with the packets of both", [][]byte{bytes.Join(chrome, nil)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newTestCachedReader(t, &datagramReader{datagrams: slices.Clone(tt.datagrams)})
			ctx := snifferContext()
			result, err := sniff(ctx, reader, false, net.Network_UDP, newSniffer(ctx))
			if err != nil || result.Protocol() != "quic" || result.Domain() != "chrome.sniff.test" {
				t.Fatalf("sniff() = (%v, %v), want quic chrome.sniff.test", result, err)
			}
			lent := reader.Datagrams()
			if len(lent) != len(tt.datagrams) {
				t.Fatalf("the cached reader lends %d datagrams, want %d", len(lent), len(tt.datagrams))
			}
			for i := range lent {
				if !bytes.Equal(lent[i], tt.datagrams[i]) {
					t.Fatalf("datagram %d is lent as %d bytes, want its %d bytes unchanged", i, len(lent[i]), len(tt.datagrams[i]))
				}
			}
		})
	}
}

// The datagrams the cached reader lends are its cached buffers, so it must
// forget them once it hands the buffers on or releases them.
func TestCachedReaderForgetsLentDatagrams(t *testing.T) {
	for name, finish := range map[string]func(*testing.T, *cachedReader){
		"read": func(t *testing.T, r *cachedReader) {
			forwarded, err := r.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			buf.ReleaseMulti(forwarded)
		},
		"interrupted": func(_ *testing.T, r *cachedReader) { r.Interrupt() },
	} {
		t.Run(name, func(t *testing.T) {
			reader := newTestCachedReader(t, &datagramReader{datagrams: [][]byte{[]byte("datagram")}})
			if _, err := reader.Cache(time.Second); err != nil {
				t.Fatal(err)
			}
			if len(reader.Datagrams()) != 1 {
				t.Fatal("the cached reader lends no datagram")
			}
			finish(t, reader)
			if reader.datagrams != nil {
				t.Fatal("the cached reader keeps the datagrams it lent after their buffers left it")
			}
		})
	}
}

// The cached reader lends the datagrams the payload it returned holds whole:
// of several buffers, Cache copies no more than its scratch buffer holds.
func TestCachedReaderLendsTheDatagramsOfThePayload(t *testing.T) {
	datagrams := make([][]byte, 5)
	for i := range datagrams {
		datagrams[i] = bytes.Repeat([]byte{byte(i + 1)}, 8000)
	}
	reader := newTestCachedReader(t, &datagramReader{datagrams: slices.Clone(datagrams)})
	var payload []byte
	for range datagrams {
		var err error
		if payload, err = reader.Cache(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if len(payload) < 4*8000 || len(payload) >= 5*8000 {
		t.Fatalf("the payload holds %d bytes; the test needs four datagrams of 8000 bytes in it whole and the fifth cut", len(payload))
	}
	lent := reader.Datagrams()
	if len(lent) != 4 {
		t.Fatalf("the cached reader lends %d datagrams, want the 4 the payload holds whole", len(lent))
	}
	for i := range lent {
		if !bytes.Equal(lent[i], datagrams[i]) {
			t.Fatalf("datagram %d is lent other than it was cached", i)
		}
	}
}
