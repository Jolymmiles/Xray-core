package dispatcher

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// readQUICCorpus returns the first n client datagrams of a capture in the
// QUIC sniffer's corpus; see its PROVENANCE.md.
func readQUICCorpus(t *testing.T, prefix string, n int) [][]byte {
	t.Helper()
	datagrams := make([][]byte, n)
	for i := range datagrams {
		datagram, err := os.ReadFile(filepath.Join("..", "..", "common", "protocol", "quic", "testdata", prefix+"-"+strconv.Itoa(i)+".bin"))
		if err != nil {
			t.Fatal(err)
		}
		datagrams[i] = datagram
	}
	return datagrams
}

// datagramReader yields one datagram per read, each in its own buffer, as the
// link of a UDP inbound does, and times out once all have been read.
type datagramReader struct {
	datagrams [][]byte
}

// ReadMultiBuffer returns the next datagram in a buffer of its own, or io.EOF
// once all have been read.
func (r *datagramReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.datagrams) == 0 {
		return nil, io.EOF
	}
	b := buf.New()
	if _, err := b.Write(r.datagrams[0]); err != nil {
		b.Release()
		return nil, err
	}
	r.datagrams = r.datagrams[1:]
	return buf.MultiBuffer{b}, nil
}

// ReadMultiBufferTimeout returns the next datagram, or buf.ErrReadTimeout once
// all have been read, like a link that has nothing more to deliver.
func (r *datagramReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	if len(r.datagrams) == 0 {
		return nil, buf.ErrReadTimeout
	}
	return r.ReadMultiBuffer()
}

// cachedReader.Cache lends its only cached buffer to the sniffers instead of
// copying it, and the dispatcher forwards that buffer afterwards, so no default
// sniffer may write to the payload it is given.
func TestDefaultSniffersLeaveBorrowedPayloadIntact(t *testing.T) {
	payloads := map[string][]byte{
		"tls":                       tlsClientHello(),
		"http":                      []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"bittorrent":                vPeerHandshake(),
		"utp":                       vUTPSYN(),
		"dht":                       vDHTGetPeers(),
		"udp tracker":               vUDPTrackerConnect(),
		"quic, whole ClientHello":   readQUICCorpus(t, "quic-ngtcp2-1.11", 1)[0],
		"quic, part of ClientHello": readQUICCorpus(t, "quic-chrome153", 1)[0],
	}
	ctx := snifferContext()
	for index, sniffer := range defaultProtocolSniffers {
		for name, payload := range payloads {
			borrowed := bytes.Clone(payload)
			_, _ = sniffer.protocolSniffer(ctx, borrowed)
			if !bytes.Equal(borrowed, payload) {
				t.Errorf("default sniffer %d modified the %s payload", index, name)
			}
		}
	}
}

// Sniffing a QUIC flow must leave every cached datagram as it was received,
// whether the ClientHello fits one datagram or spans several that are cached
// one at a time, because the dispatcher forwards those datagrams afterwards.
func TestSniffQUICFromCachedDatagramsKeepsThemIntact(t *testing.T) {
	tests := []struct {
		name      string
		datagrams [][]byte
		domain    string
	}{
		{"ClientHello in one datagram", readQUICCorpus(t, "quic-ngtcp2-1.11", 1), "ngtcp2.sniff.test"},
		{"ClientHello across datagrams", readQUICCorpus(t, "quic-chrome153", 2), "chrome.sniff.test"},
		{"ClientHello across padded datagrams", readQUICCorpus(t, "quic-firefox153esr", 2), "firefox.sniff.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			received := make([][]byte, len(tt.datagrams))
			for i, datagram := range tt.datagrams {
				received[i] = bytes.Clone(datagram)
			}
			reader := newCachedReader(&datagramReader{datagrams: received})
			ctx := snifferContext()

			result, err := sniff(ctx, reader, false, net.Network_UDP, newSniffer(ctx))
			if err != nil {
				t.Errorf("sniff() error = %v, want quic %q", err, tt.domain)
			} else if result.Protocol() != "quic" || result.Domain() != tt.domain {
				t.Errorf("sniff() = %s %q, want quic %q", result.Protocol(), result.Domain(), tt.domain)
			}

			forwarded, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(forwarded)
			if len(forwarded) != len(tt.datagrams) {
				t.Fatalf("forwarded %d buffers, want one per datagram (%d)", len(forwarded), len(tt.datagrams))
			}
			for i, b := range forwarded {
				if !bytes.Equal(b.Bytes(), tt.datagrams[i]) {
					t.Errorf("forwarded datagram %d differs from the one received", i)
				}
			}
		})
	}
}
