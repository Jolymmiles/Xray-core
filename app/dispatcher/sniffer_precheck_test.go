package dispatcher

import (
	"context"
	gotls "crypto/tls"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/core"
)

// snifferContext supplies the core instance newFakeDNSSniffer requires.
func snifferContext() context.Context {
	return context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
}

// TestSniffHTTPNeverAsksForMoreData documents the precondition behind the HTTP
// precheck in Sniff: SniffHTTP decides from the request line alone and never
// reports ErrProtoNeedMoreData. Only the TLS and QUIC sniffers do. If SniffHTTP
// ever gains that return, Sniff must learn to keep the remaining sniffers
// pending instead of discarding them.
func TestSniffHTTPNeverAsksForMoreData(t *testing.T) {
	payloads := [][]byte{
		nil,
		[]byte(""),
		[]byte("G"),
		[]byte("GE"),
		[]byte("GET"),
		[]byte("GET "),
		[]byte("GET /"),
		[]byte("GET / HTTP/1.1\r\n"),
		[]byte("GET / HTTP/1.1\r\nHost: "),
		[]byte("GET / HTTP/1.1\r\nHost: example.com"),
		[]byte("POST /x HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("\x16\x03\x01\x00\x01"),
		[]byte("\x13BitTorrent protocol"),
		[]byte("not a protocol at all"),
	}

	for _, payload := range payloads {
		_, err := http.SniffHTTP(payload, context.Background())
		if err == protocol.ErrProtoNeedMoreData {
			t.Fatalf("SniffHTTP(%q) returned ErrProtoNeedMoreData; the precheck in Sniff must be revisited", payload)
		}
	}
}

// TestSniffKeepsPendingSniffersAfterNoClue proves that a payload no sniffer can
// classify yet leaves the remaining sniffers armed, so a later, longer payload
// is still matched. A BitTorrent handshake that arrives after an inconclusive
// first read is the case that matters in practice.
func TestSniffKeepsPendingSniffersAfterNoClue(t *testing.T) {
	sniffer := NewSniffer(snifferContext())

	if _, err := sniffer.Sniff(snifferContext(), []byte("\x13Bit"), net.Network_TCP); err != common.ErrNoClue {
		t.Fatalf("first Sniff returned %v, want ErrNoClue", err)
	}

	result, err := sniffer.Sniff(snifferContext(), []byte("\x13BitTorrent protocol"), net.Network_TCP)
	if err != nil {
		t.Fatalf("second Sniff returned %v, want a bittorrent match", err)
	}
	if got := result.Protocol(); got != "bittorrent" {
		t.Fatalf("second Sniff matched %q, want bittorrent", got)
	}
}

// TestSniffPrecheckMatchesFullSweep pins the HTTP fast path against the plain
// sweep: prechecking HTTP before the loop must not change which protocol wins.
func TestSniffPrecheckMatchesFullSweep(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"http request", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), "http1"},
		{"tls client hello", tlsClientHello(), "tls"},
		{"bittorrent handshake", []byte("\x13BitTorrent protocol"), "bittorrent"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sniffer := NewSniffer(snifferContext())
			result, err := sniffer.Sniff(snifferContext(), tc.payload, net.Network_TCP)
			if err != nil {
				t.Fatalf("Sniff returned %v, want %s", err, tc.want)
			}
			if got := result.Protocol(); got != tc.want {
				t.Fatalf("Sniff matched %q, want %q", got, tc.want)
			}
		})
	}
}

// tlsClientHello captures a genuine ClientHello by starting a real handshake
// against a pipe and reading the first record the standard library emits.
func tlsClientHello() []byte {
	client, server := stdnet.Pipe()
	defer client.Close()
	defer server.Close()

	captured := make(chan []byte, 1)
	go func() {
		record := make([]byte, 4096)
		n, err := server.Read(record)
		if err != nil {
			captured <- nil
			return
		}
		captured <- record[:n]
	}()

	conn := gotls.Client(client, &gotls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = conn.HandshakeContext(ctx)

	return <-captured
}

func BenchmarkSniff(b *testing.B) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"http", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"tls", tlsClientHello()},
		{"bittorrent", []byte("\x13BitTorrent protocol")},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				sniffer := NewSniffer(snifferContext())
				if _, err := sniffer.Sniff(snifferContext(), tc.payload, net.Network_TCP); err != nil {
					b.Fatalf("Sniff: %v", err)
				}
			}
		})
	}
}
