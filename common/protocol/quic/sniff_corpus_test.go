package quic_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	quicgo "github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
)

// readCorpus returns the first n datagrams of a capture in testdata; see
// testdata/PROVENANCE.md.
func readCorpus(t *testing.T, prefix string, n int) [][]byte {
	t.Helper()
	datagrams := make([][]byte, n)
	for i := range datagrams {
		datagram, err := os.ReadFile(filepath.Join("testdata", prefix+"-"+strconv.Itoa(i)+".bin"))
		if err != nil {
			t.Fatal(err)
		}
		datagrams[i] = datagram
	}
	return datagrams
}

// assertSniffDatagrams sniffs the first i datagrams of a flow for every i up
// to len(datagrams), concatenated as the dispatcher caches them. Sniffing
// must ask for more data until all of them have arrived, then report domain,
// and it must never modify the datagrams, which the dispatcher forwards.
func assertSniffDatagrams(t *testing.T, datagrams [][]byte, domain string) {
	t.Helper()
	for i := 1; i <= len(datagrams); i++ {
		flow := bytes.Join(datagrams[:i], nil)
		received := bytes.Clone(flow)
		header, err := quic.SniffQUIC(flow)
		if !bytes.Equal(flow, received) {
			t.Fatalf("SniffQUIC modified the first %d datagrams", i)
		}
		if i < len(datagrams) {
			if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
				t.Fatalf("after %d of %d datagrams: SniffQUIC() = (%v, %v), want more data", i, len(datagrams), header, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("after %d datagrams: SniffQUIC() error = %v, want %q", i, err, domain)
		}
		if header.Domain() != domain {
			t.Fatalf("after %d datagrams: SniffQUIC() domain = %q, want %q", i, header.Domain(), domain)
		}
	}
}

// Modern clients split their ClientHello across Initial packets, and Chrome
// shuffles its fragments; Hysteria 2.13.0 fixed sniffing them. The flows come
// from Hysteria's corpus, with the datagram counts its sniffer needs.
func TestSniffQUICClientCorpus(t *testing.T) {
	chrome := readCorpus(t, "quic-chrome153", 3)
	firefox := readCorpus(t, "quic-firefox153esr", 2)
	curl := readCorpus(t, "quic-curl8.14-openssl3.5", 2)
	tests := []struct {
		name      string
		datagrams [][]byte
		domain    string
	}{
		{"Chrome 153", chrome[:2], "chrome.sniff.test"},
		{"Chrome 153 reordered", [][]byte{chrome[1], chrome[0]}, "chrome.sniff.test"},
		{"Chrome 153 retransmitted", [][]byte{chrome[1], chrome[2]}, "chrome.sniff.test"},
		{"Firefox 153 ESR", firefox, "firefox.sniff.test"},
		{"Firefox 153 ESR reordered", [][]byte{firefox[1], firefox[0]}, "firefox.sniff.test"},
		{"curl 8.14 (OpenSSL 3.5)", curl, "curl.sniff.test"},
		{"quiche retransmits its first datagram", readCorpus(t, "quic-quiche", 3), "quiche.sniff.test"},
		{"ngtcp2 1.11", readCorpus(t, "quic-ngtcp2-1.11", 1), "ngtcp2.sniff.test"},
		{"aioquic 1.2", readCorpus(t, "quic-aioquic1.2", 1), "aioquic.sniff.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSniffDatagrams(t, tt.datagrams, tt.domain)
		})
	}
}

// Datagrams that are not client Initial packets of a known version are
// rejected outright instead of keeping the sniffer waiting.
func TestSniffQUICCorpusRejections(t *testing.T) {
	chrome := readCorpus(t, "quic-chrome153", 1)
	tests := []struct {
		name     string
		datagram []byte
	}{
		{"not QUIC", []byte("oh my sweet summer child")},
		{"unsupported version", append([]byte{0xc0, 0xff, 0x00, 0x00, 0x1d}, chrome[0][5:]...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := quic.SniffQUIC(tt.datagram)
			if err == nil || errors.Is(err, protocol.ErrProtoNeedMoreData) {
				t.Fatalf("SniffQUIC() error = %v, want a rejection", err)
			}
		})
	}
}

// quicGoFirstFlight returns the first n datagrams a quic-go client dialing
// serverName sends, the stack the Hysteria and XHTTP/3 clients use.
func quicGoFirstFlight(t *testing.T, config *quicgo.Config, serverName string, n int) [][]byte {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	dialDone := make(chan struct{})
	defer func() {
		cancel()
		<-dialDone
	}()
	go func() {
		defer close(dialDone)
		tlsConfig := &tls.Config{ServerName: serverName, NextProtos: []string{"h3"}}
		_, _ = quicgo.DialAddr(ctx, listener.LocalAddr().String(), tlsConfig, config)
	}()

	datagrams := make([][]byte, 0, n)
	buffer := make([]byte, 2048)
	for len(datagrams) < n {
		if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		length, _, err := listener.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		datagrams = append(datagrams, slices.Clone(buffer[:length]))
	}
	return datagrams
}

func TestSniffQUICGoFirstFlight(t *testing.T) {
	tests := []struct {
		name   string
		config *quicgo.Config
	}{
		{"v1", &quicgo.Config{}},
		{"v2", &quicgo.Config{Versions: []quicgo.Version{quicgo.Version2}}},
		{"Chrome parrot", &quicgo.Config{ChromeParrot: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			datagrams := quicGoFirstFlight(t, tt.config, "quic-go.sniff.test", 2)
			assertSniffDatagrams(t, datagrams, "quic-go.sniff.test")
		})
	}
}
