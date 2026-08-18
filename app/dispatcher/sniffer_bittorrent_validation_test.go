package dispatcher

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// Builders here mirror the wire formats used in
// common/protocol/bittorrent/realworld_validation_test.go; they are
// duplicated so this package-level validation does not depend on test
// helpers of another package.

func vPeerHandshake() []byte {
	r := rand.New(rand.NewSource(1))
	h := make([]byte, 0, 68)
	h = append(h, 19)
	h = append(h, "BitTorrent protocol"...)
	h = append(h, 0, 0, 0, 0, 0, 0x10, 0, 0x05) // BEP10 + BEP5 + BEP6
	info, err := hex.DecodeString("dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c")
	if err != nil {
		panic(err)
	}
	h = append(h, info...)
	h = append(h, "-qB4530-"...)
	const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for len(h) < 68 {
		h = append(h, alnum[r.Intn(len(alnum))])
	}
	return h
}

func vUTPData() []byte {
	b := make([]byte, 20, 1040)
	b[0] = 0x01 // ST_DATA, version 1
	b[1] = 0    // no extensions
	binary.BigEndian.PutUint16(b[2:4], 0x07E1)
	binary.BigEndian.PutUint32(b[4:8], uint32(time.Now().UnixMicro()))
	binary.BigEndian.PutUint32(b[8:12], 900)
	binary.BigEndian.PutUint32(b[12:16], 0x100000)
	binary.BigEndian.PutUint16(b[16:18], 101)
	binary.BigEndian.PutUint16(b[18:20], 100)
	r := rand.New(rand.NewSource(2))
	for len(b) < 1040 {
		b = append(b, byte(r.Intn(256)))
	}
	return b
}

func vDHTGetPeers() []byte {
	nodeID := make([]byte, 20)
	info, _ := hex.DecodeString("dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c")
	var sb strings.Builder
	sb.WriteString("d1:ad2:id20:")
	sb.Write(nodeID)
	sb.WriteString("9:info_hash20:")
	sb.Write(info)
	sb.WriteString("e1:q9:get_peers1:t2:aa1:y1:qe")
	return []byte(sb.String())
}

func vUDPTrackerConnect() []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:4], 0x417)
	binary.BigEndian.PutUint32(b[4:8], 0x27101980)
	binary.BigEndian.PutUint32(b[12:16], 0xDEADBEEF)
	return b
}

// TestSniffTorrentTrafficThroughFullChain runs the corpus through the same
// Sniffer the dispatcher uses, proving what reaches content.Protocol() and
// therefore the router's protocol matcher.
func TestSniffTorrentTrafficThroughFullChain(t *testing.T) {
	t.Run("tcp handshake of a real client is routed as bittorrent", func(t *testing.T) {
		result, err := NewSniffer(snifferContext()).Sniff(snifferContext(), vPeerHandshake(), net.Network_TCP)
		if err != nil {
			t.Fatalf("Sniff returned %v, want bittorrent", err)
		}
		if got := result.Protocol(); got != "bittorrent" {
			t.Fatalf("protocol = %q, want bittorrent", got)
		}
	})

	t.Run("http tracker announce is http, not bittorrent", func(t *testing.T) {
		request := "GET /announce?info_hash=x&peer_id=-qB4530-xk2f9amqbtt3&port=6881 HTTP/1.1\r\nHost: tracker.example.com\r\n\r\n"
		result, err := NewSniffer(snifferContext()).Sniff(snifferContext(), []byte(request), net.Network_TCP)
		if err != nil {
			t.Fatalf("Sniff returned %v, want http1", err)
		}
		if got := result.Protocol(); got == "bittorrent" {
			t.Fatalf("tracker HTTP request classified as bittorrent")
		}
	})

	t.Run("utp data packet is routed as bittorrent", func(t *testing.T) {
		result, err := NewSniffer(snifferContext()).Sniff(snifferContext(), vUTPData(), net.Network_UDP)
		if err != nil {
			t.Fatalf("Sniff returned %v, want bittorrent", err)
		}
		if got := result.Protocol(); got != "bittorrent" {
			t.Fatalf("protocol = %q, want bittorrent", got)
		}
	})

	t.Run("dht query is routed as bittorrent", func(t *testing.T) {
		result, err := NewSniffer(snifferContext()).Sniff(snifferContext(), vDHTGetPeers(), net.Network_UDP)
		if err != nil {
			t.Fatalf("Sniff returned %v, want bittorrent", err)
		}
		if got := result.Protocol(); got != "bittorrent" {
			t.Fatalf("protocol = %q, want bittorrent", got)
		}
	})

	t.Run("udp tracker connect is routed as bittorrent", func(t *testing.T) {
		result, err := NewSniffer(snifferContext()).Sniff(snifferContext(), vUDPTrackerConnect(), net.Network_UDP)
		if err != nil {
			t.Fatalf("Sniff returned %v, want bittorrent", err)
		}
		if got := result.Protocol(); got != "bittorrent" {
			t.Fatalf("protocol = %q, want bittorrent", got)
		}
	})
}
