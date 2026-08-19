package bittorrent

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
)

// This file validates the BitTorrent sniffers against a corpus of realistic,
// wire-format-accurate torrent traffic. Builders below follow the published
// protocol specifications (BEP 3 for the TCP handshake, BEP 29 for uTP,
// BEP 5 for DHT, BEP 14 for LSD, BEP 15 for UDP trackers) so a green run here
// is evidence about real client traffic, not synthetic byte patterns.

// newMockRand returns a deterministic generator so corpus payloads are
// reproducible across runs.
func newMockRand(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}

// azureusStylePeerID builds a 20-byte peer id like "-qB4530-xk2f9amqbtt3",
// the convention of most real clients.
func azureusStylePeerID(prefix string, r *rand.Rand) [20]byte {
	var id [20]byte
	copy(id[:], prefix)
	const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for i := len(prefix); i < len(id); i++ {
		id[i] = alnum[r.Intn(len(alnum))]
	}
	return id
}

func infoHashFromHex(s string) [20]byte {
	var h [20]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	copy(h[:], b)
	return h
}

func randomInfoHash(r *rand.Rand) [20]byte {
	var h [20]byte
	for i := range h {
		h[i] = byte(r.Intn(256))
	}
	return h
}

// peerHandshake builds the 68-byte TCP handshake from BEP 3:
// pstrlen(1) + "BitTorrent protocol"(19) + reserved(8) + info hash(20) + peer id(20).
func peerHandshake(reserved [8]byte, infoHash, peerID [20]byte) []byte {
	h := make([]byte, 0, 68)
	h = append(h, 19)
	h = append(h, "BitTorrent protocol"...)
	h = append(h, reserved[:]...)
	h = append(h, infoHash[:]...)
	h = append(h, peerID[:]...)
	return h
}

// Reserved-byte conventions seen in real clients (big-endian bit field):
//   - BEP 10 extension protocol: reserved[5] |= 0x10
//   - BEP 5 DHT: reserved[7] |= 0x01
//   - BEP 6 fast extension: reserved[7] |= 0x04
//   - BEP 52 BitTorrent v2: reserved[5] |= 0x04
var (
	reservedDHTPlusFast   = [8]byte{0, 0, 0, 0, 0, 0x10, 0, 0x05}
	reservedExtensionOnly = [8]byte{0, 0, 0, 0, 0, 0x10, 0, 0}
	reservedExtensionDHT  = [8]byte{0, 0, 0, 0, 0, 0x10, 0, 0x01}
	reservedWithV2Bit     = [8]byte{0, 0, 0, 0, 0, 0x14, 0, 0x01}
	reservedAllZero       = [8]byte{}
)

// bigBuckBunnyInfoHash is the info hash of the freely licensed
// Big Buck Bunny torrent, used here as an example of a real public swarm.
var bigBuckBunnyInfoHash = infoHashFromHex("dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c")

// utpExt is one extension header that follows the fixed 20-byte uTP header.
type utpExt struct {
	id   byte
	data []byte
}

var sackExtension = utpExt{id: 1, data: []byte{0x80, 0x00, 0x00, 0x01}}

// closeReasonExtension mirrors libtorrent's utp_close_reason extension (id 3):
// next id 0, length 4, big-endian close reason code.
var closeReasonExtension = utpExt{id: 3, data: []byte{0x00, 0x00, 0x03, 0xEC}}

// utpPacket builds a packet in the real BEP 29 wire layout:
//
//	type_ver(1) ext(1) connid(2) ts_us(4) ts_diff_us(4) wnd(4) seq(2) ack(2)
//	followed by extension headers: next_id(1) len(1) data(len)
//
// tsMicro is the sender's monotonic-clock microseconds truncated to 32 bits
// (libutp: CLOCK_MONOTONIC; libtorrent: steady_clock), which is what real
// stacks put on the wire. The sniffer must treat the field as opaque.
func utpPacket(typ byte, connID uint16, tsMicro, tsDiffMicro, wnd uint32, seq, ack uint16, exts []utpExt, payload []byte) []byte {
	firstExt := byte(0)
	if len(exts) > 0 {
		firstExt = exts[0].id
	}
	b := make([]byte, 20, 20+8*len(exts)+len(payload))
	b[0] = typ<<4 | 1
	b[1] = firstExt
	binary.BigEndian.PutUint16(b[2:4], connID)
	binary.BigEndian.PutUint32(b[4:8], tsMicro)
	binary.BigEndian.PutUint32(b[8:12], tsDiffMicro)
	binary.BigEndian.PutUint32(b[12:16], wnd)
	binary.BigEndian.PutUint16(b[16:18], seq)
	binary.BigEndian.PutUint16(b[18:20], ack)
	for i, e := range exts {
		next := byte(0)
		if i+1 < len(exts) {
			next = exts[i+1].id
		}
		b = append(b, next, byte(len(e.data)))
		b = append(b, e.data...)
	}
	return append(b, payload...)
}

// someTimestamp stands in for the uTP timestamp field. Deployed stacks put
// monotonic clock microseconds there (libutp: CLOCK_MONOTONIC; libtorrent:
// steady_clock truncated to 32 bits), so the value carries no epoch the
// sniffer could validate and these tests use arbitrary values.
func someTimestamp() uint32 { return uint32(time.Now().UnixNano()) }

// ST_DATA payload typical of a 16 KiB block transfer, truncated for the test.
func blockPayload(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	r.Read(b)
	return b
}

// dhtGetPeersQuery builds a BEP 5 get_peers query, the most common DHT
// message in an active swarm.
func dhtGetPeersQuery(nodeID, infoHash [20]byte) []byte {
	var sb strings.Builder
	sb.WriteString("d1:ad2:id20:")
	sb.Write(nodeID[:])
	sb.WriteString("9:info_hash20:")
	sb.Write(infoHash[:])
	sb.WriteString("e1:q9:get_peers1:t2:aa1:y1:qe")
	return []byte(sb.String())
}

func dhtFindNodeQuery(nodeID, target [20]byte) []byte {
	var sb strings.Builder
	sb.WriteString("d1:ad2:id20:")
	sb.Write(nodeID[:])
	sb.WriteString("6:target20:")
	sb.Write(target[:])
	sb.WriteString("e1:q9:find_node1:t2:ab1:y1:qe")
	return []byte(sb.String())
}

func dhtFindNodeResponse(nodeID [20]byte) []byte {
	var sb strings.Builder
	sb.WriteString("d1:rd2:id20:")
	sb.Write(nodeID[:])
	sb.WriteString("5:nodes")
	compact := make([]byte, 0, 26)
	compact = append(compact, nodeID[:6]...)
	compact = append(compact, 0x6F, 0x31) // 127.0.0.1
	compact = append(compact, 0x1A, 0xE1) // port 6881
	sb.WriteString(strconv.Itoa(len(compact)) + ":")
	sb.Write(compact)
	sb.WriteString("e1:t2:ab1:y1:re")
	return []byte(sb.String())
}

// udpTrackerConnect builds the BEP 15 connect request every UDP tracker
// session starts with: magic(8) action=0(4) transaction(4).
func udpTrackerConnect(txn uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], 0x41727101980)
	binary.BigEndian.PutUint32(b[8:12], 0)
	binary.BigEndian.PutUint32(b[12:16], txn)
	return b
}

// lsdSearch builds the BEP 14 local service discovery datagram.
func lsdSearch(infoHash [20]byte) []byte {
	return []byte("BT-SEARCH * HTTP/1.1\r\n" +
		"Host: 239.192.152.143:6771\r\n" +
		"Port: 6881\r\n" +
		"Infohash: " + hex.EncodeToString(infoHash[:]) + "\r\n" +
		"\r\n")
}

func dnsQueryFor(name string, txn, flags uint16) []byte {
	var b []byte
	b = append(b, byte(txn>>8), byte(txn), byte(flags>>8), byte(flags), 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b
}

// TestSniffRealWorldTorrentTCP feeds full 68-byte handshakes of six real
// client families through SniffBittorrent. All must be detected.
func TestSniffRealWorldTorrentTCP(t *testing.T) {
	r := newMockRand(1)
	hash2 := randomInfoHash(r)
	hash3 := randomInfoHash(r)

	cases := []struct {
		name     string
		reserved [8]byte
		peerID   string
		infoHash [20]byte
	}{
		{"qBittorrent 4.5.3 libtorrent 2.0", reservedDHTPlusFast, "-qB4530-", bigBuckBunnyInfoHash},
		{"Transmission 4.0.5", reservedExtensionOnly, "-TR4050-", hash2},
		{"Deluge 1.3.15", reservedExtensionDHT, "-DE13F0-", hash3},
		{"uTorrent 3.6.0", reservedDHTPlusFast, "-UT3600-", bigBuckBunnyInfoHash},
		{"BiglyBT 5.7.0", reservedExtensionDHT, "-AZ5700-", hash2},
		{"mainline 7.10 with v2 bit", reservedWithV2Bit, "M7-10-0--", hash3},
		{"legacy client no extensions", reservedAllZero, "01234567890123456789", bigBuckBunnyInfoHash},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := peerHandshake(tc.reserved, tc.infoHash, azureusStylePeerID(tc.peerID, r))
			header, err := SniffBittorrent(payload)
			if err != nil || header == nil {
				t.Fatalf("handshake not detected: err=%v", err)
			}
			if got := header.Protocol(); got != "bittorrent" {
				t.Fatalf("protocol = %q, want bittorrent", got)
			}
		})
	}

	t.Run("truncated handshake header only", func(t *testing.T) {
		payload := peerHandshake(reservedDHTPlusFast, bigBuckBunnyInfoHash, azureusStylePeerID("-qB4530-", r))[:20]
		if header, err := SniffBittorrent(payload); err != nil || header == nil {
			t.Fatalf("20-byte handshake prefix not detected: err=%v", err)
		}
	})
}

// TestSniffTorrentTCPFailureModes covers inputs that must not be classified
// as BitTorrent: other protocols riding TCP and malformed handshakes.
func TestSniffTorrentTCPFailureModes(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"http tracker announce", []byte("GET /announce?info_hash=%dd%82U%ec%dc%7caU%f0%bb%f8%13%23%d8pb%db%1f6%d1c&peer_id=-qB4530-xk2f9amqbtt3&port=6881&uploaded=0&downloaded=0&left=0&compact=1&event=started HTTP/1.1\r\nHost: tracker.example.com:80\r\n\r\n")},
		{"tls client hello prefix", []byte{0x16, 0x03, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x7c, 0x03, 0x03}},
		{"ssh banner", []byte("SSH-2.0-OpenSSH_9.6\r\n")},
		{"bep10 extended handshake message without tcp handshake", append([]byte{0, 0, 0, 40}, []byte("d1:md11:ut_metadatai1e11:lt_donthavei1ee1:pi6881e1:v15:qBittorrent 4.5.3e")...)},
		{"wrong protocol name", append([]byte{19}, []byte("BitTorrent protocoX")...)},
		{"wrong pstrlen", append([]byte{18}, []byte("BitTorrent protocol")...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if header, err := SniffBittorrent(tc.payload); err == nil && header != nil {
				t.Fatalf("classified as bittorrent, want rejection")
			}
		})
	}

	t.Run("short prefix keeps sniffer pending", func(t *testing.T) {
		r := newMockRand(2)
		full := peerHandshake(reservedDHTPlusFast, bigBuckBunnyInfoHash, azureusStylePeerID("-qB4530-", r))
		if _, err := SniffBittorrent(full[:10]); err != common.ErrNoClue {
			t.Fatalf("10-byte prefix returned %v, want ErrNoClue", err)
		}
		if header, err := SniffBittorrent(full); err != nil || header == nil {
			t.Fatalf("full handshake after short prefix not detected: err=%v", err)
		}
	})
}

// TestSniffRealWorldUTP feeds wire-format-accurate uTP packets of every
// message type through SniffUTP. These are the datagram shapes qBittorrent,
// Transmission and libtorrent clients put on the wire for the majority of
// peer traffic, so every case must be detected.
func TestSniffRealWorldUTP(t *testing.T) {
	r := newMockRand(3)
	ts := someTimestamp()

	cases := []struct {
		name    string
		payload []byte
	}{
		{"ST_SYN connection setup", utpPacket(4, 0xC0A8, ts, 0, 0x1FC000, 1, 0, nil, nil)},
		{"ST_STATE ack", utpPacket(2, 0xC0A8, ts, 1250, 0x1FC000, 57, 56, nil, nil)},
		{"ST_DATA 1400 byte block", utpPacket(0, 0x07E1, ts, 900, 0x100000, 101, 100, nil, blockPayload(r, 1400))},
		{"ST_DATA with SACK after loss", utpPacket(0, 0x07E1, ts, 900, 0x100000, 101, 100, []utpExt{sackExtension}, blockPayload(r, 1200))},
		{"ST_STATE with SACK", utpPacket(2, 0x1F90, ts, 640, 0x200000, 88, 87, []utpExt{sackExtension}, nil)},
		{"ST_STATE with close reason", utpPacket(2, 0x07E1, ts, 900, 0x1FC000, 55, 54, []utpExt{closeReasonExtension}, nil)},
		{"ST_DATA with SACK then close reason", utpPacket(0, 0x07E1, ts, 900, 0x100000, 101, 100, []utpExt{sackExtension, closeReasonExtension}, blockPayload(r, 400))},
		{"ST_FIN graceful close", utpPacket(1, 0x07E1, ts, 200, 0x1FC000, 250, 249, nil, nil)},
		{"ST_RESET abort", utpPacket(3, 0x07E1, ts, 200, 0, 250, 249, nil, nil)},
		{"ST_DATA with zero timestamp", utpPacket(0, 0x07E1, 0, 900, 0x100000, 5, 4, nil, blockPayload(r, 500))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header, err := SniffUTP(tc.payload)
			if err != nil || header == nil {
				t.Fatalf("uTP packet not detected: err=%v", err)
			}
			if got := header.Protocol(); got != "bittorrent" {
				t.Fatalf("protocol = %q, want bittorrent", got)
			}
		})
	}
}

// TestSniffUTPIgnoresTimestampClockBase pins that detection never assumes a
// clock base for the timestamp field. Deployed stacks put monotonic
// microseconds there, not Unix time: libutp reads CLOCK_MONOTONIC (falling
// back to gettimeofday), and libtorrent uses steady_clock truncated to the
// low 32 bits. The previous implementation compared the field against
// time.Now().UnixMicro() with a window expressed in nanoseconds, which
// rejected every packet any client has ever sent.
func TestSniffUTPIgnoresTimestampClockBase(t *testing.T) {
	timestamps := []uint32{
		0,
		1,
		123456789,
		0xDEADBEEF,
		math.MaxUint32,
		uint32(time.Now().UnixMicro()),
		uint32(time.Now().UnixNano()),
	}
	for _, ts := range timestamps {
		packet := utpPacket(0, 0x07E1, ts, 900, 0x100000, 101, 100, nil, blockPayload(newMockRand(5), 16))
		header, err := SniffUTP(packet)
		if err != nil || header == nil {
			t.Fatalf("timestamp %d (%#x) rejected: %v", ts, ts, err)
		}
	}
}

// TestSniffUTPIgnoresDNSQueries is a production regression test. A DNS query
// whose transaction id starts with 0x01/0x11/0x21/0x31/0x41 and ends with
// 0x00 collides with the uTP header shape: the type and version nibbles
// match, the low transaction byte reads as "no extension", and the query
// flags 0x0100 read as a non-zero connection id. A v26.8.21 deployment
// observed dozens of such flows per half hour routed to the bittorrent
// block outbound, breaking name resolution for unlucky queries.
func TestSniffUTPIgnoresDNSQueries(t *testing.T) {
	names := []string{"tracker.example.com", "ya.ru", "roblox.com", "a.very.long.domain.name.with.many.labels.example.org"}
	for i, txn := range []uint16{0x0100, 0x1100, 0x2100, 0x3100, 0x4100} {
		for _, name := range names {
			query := dnsQueryFor(name, txn, 0x0100)
			if header, err := SniffUTP(query); err == nil && header != nil {
				t.Fatalf("DNS query with txn %#04x for %s classified as bittorrent", txn, name)
			}
		}
		_ = i
	}

	t.Run("edns variant", func(t *testing.T) {
		query := dnsQueryFor("tracker.example.com", 0x3100, 0x0100)
		// add EDNS0 OPT record: ARCOUNT=1 and a trailing record
		query[11] = 1
		query = append(query, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00)
		if header, err := SniffUTP(query); err == nil && header != nil {
			t.Fatalf("EDNS query classified as bittorrent")
		}
	})

	// Shapes below were verified live against Cloudflare, Google, Quad9,
	// OpenDNS, AdGuard, Yandex, AliDNS and DNSPod on 2026-08-19: every
	// resolver answered each query. All of them slipped past the first
	// revision of the DNS exclusion and were reported as bittorrent by a
	// v26.8.22 deployment (8.8.8.8:53, auto-banned user).
	for name, query := range map[string][]byte{
		"edns with two additional records": ednsTwoExtraQuery(),
		"two questions":                    twoQuestionQuery(),
		"trailing garbage":                 append(dnsQueryFor("tracker.example.com", 0x3100, 0x0100), 0xDE, 0xAD, 0xBE, 0xEF),
		"dynamic update opcode":            dnsQueryFor("office.example.com", 0x3100, 0x2800),
		"query with answer section":        answerCarryingQuery(),
	} {
		if header, err := SniffUTP(query); err == nil && header != nil {
			t.Fatalf("%s classified as bittorrent", name)
		}
	}
}

func ednsTwoExtraQuery() []byte {
	query := dnsQueryFor("tracker.example.com", 0x3100, 0x0100)
	query[11] = 2 // ARCOUNT=2
	// OPT record plus one A record
	query = append(query, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00)
	query = append(query, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00)
	query = append(query, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 8, 8, 8, 8)
	return query
}

func twoQuestionQuery() []byte {
	query := dnsQueryFor("a.tracker.example.com", 0x3100, 0x0100)
	query[5] = 2 // QDCOUNT=2
	second := dnsQueryFor("b.tracker.example.com", 0, 0x0100)
	query = append(query, second[12:]...)
	return query
}

func answerCarryingQuery() []byte {
	query := dnsQueryFor("tracker.example.com", 0x3100, 0x0100)
	query[7] = 1 // ANCOUNT=1
	query = append(query, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00)
	query = append(query, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4)
	return query
}

// TestSniffUTPRejectsNonUTPTraffic proves the uTP sniffer claims no other
// UDP protocol, including torrent traffic that belongs to the DHT and
// tracker sniffers rather than to uTP.
func TestSniffUTPRejectsNonUTPTraffic(t *testing.T) {
	r := newMockRand(4)
	nodeID := randomInfoHash(r)
	wgTail := blockPayload(r, 120)

	cases := []struct {
		name    string
		payload []byte
	}{
		{"dht get_peers query", dhtGetPeersQuery(nodeID, bigBuckBunnyInfoHash)},
		{"dht find_node query", dhtFindNodeQuery(nodeID, randomInfoHash(r))},
		{"dht find_node response", dhtFindNodeResponse(nodeID)},
		{"udp tracker connect", udpTrackerConnect(0xDEADBEEF)},
		{"lsd multicast", lsdSearch(bigBuckBunnyInfoHash)},
		{"dns query", dnsQueryFor("tracker.example.com", 0x1234, 0x0100)},
		{"dns query with uTP-compatible first nibbles", dnsQueryFor("tracker.example.com", 0x3101, 0x0100)},
		{"ntp client request", append([]byte{0x1B}, make([]byte, 47)...)},
		{"wireguard handshake initiation", append([]byte{0x01, 0, 0, 0}, wgTail...)},
		{"wireguard transport data", append([]byte{0x04, 0, 0, 0}, blockPayload(r, 60)...)},
		{"wireguard-like all-zero header", append([]byte{0x01, 0x00, 0x00, 0x00}, make([]byte, 24)...)},
		{"utp-shaped junk with unknown extension id", append([]byte{0x01, 0x05}, blockPayload(r, 30)...)},
		{"utp-shaped junk with type 5", append([]byte{0x51, 0x00, 0x12, 0x34}, blockPayload(r, 30)...)},
		{"quic v1 initial header", append([]byte{0xC3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x20, 0x00}, blockPayload(r, 1190)...)},
		{"random datagram", blockPayload(r, 96)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if header, err := SniffUTP(tc.payload); err == nil && header != nil {
				t.Fatalf("classified as bittorrent, want rejection")
			}
		})
	}
}
