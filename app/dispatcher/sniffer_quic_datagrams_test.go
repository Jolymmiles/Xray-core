package dispatcher

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
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
			withoutPadding(t, aioquic, 673), ngtcp2}, "ngtcp2.sniff.test"},
		{"short datagram with the start of the ClientHello, then its end", [][]byte{
			withoutPadding(t, firefox[0], 259), firefox[1]}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newCachedReader(&datagramReader{datagrams: tt.datagrams})
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
