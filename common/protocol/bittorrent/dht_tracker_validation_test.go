package bittorrent

import (
	"strings"
	"testing"
)

// This file validates the DHT (BEP 5) and UDP tracker (BEP 15) sniffers
// against messages shaped like the ones libtorrent's kademlia and
// udp_tracker_connection code puts on the wire: one bencoded dictionary per
// datagram, keys as written by libtorrent's entry encoder, query names from
// its dispatch table (ping, find_node, get_peers, announce_peer, get, put,
// sample_infohashes).

// dhtDict wraps raw bencode fragments into a dictionary.
func dhtDict(parts ...string) []byte {
	var sb strings.Builder
	sb.WriteByte('d')
	for _, p := range parts {
		sb.WriteString(p)
	}
	sb.WriteByte('e')
	return []byte(sb.String())
}

// TestSniffRealWorldDHT feeds every KRPC message kind a mainline DHT node
// exchanges through SniffDHT. All must be detected.
func TestSniffRealWorldDHT(t *testing.T) {
	nodeID := randomInfoHash(newMockRand(11))
	target := randomInfoHash(newMockRand(12))
	tok := string([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	compact1 := string([]byte{127, 0, 0, 1, 0x1A, 0xE1})
	compact2 := string([]byte{192, 168, 1, 4, 0x1A, 0xE2})
	sampleA := randomInfoHash(newMockRand(13))
	sampleB := randomInfoHash(newMockRand(14))
	samples := string(sampleA[:]) + string(sampleB[:])

	cases := []struct {
		name    string
		payload []byte
	}{
		{"ping query", dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:q4:ping", "1:t2:ab", "1:v4:LT2H", "1:y1:q")},
		{"find_node query", dhtDict("1:ad2:id20:"+string(nodeID[:])+"6:target20:"+string(target[:])+"e", "1:q9:find_node", "1:t4:abcd", "1:y1:q")},
		{"get_peers query", dhtDict("1:ad2:id20:"+string(nodeID[:])+"9:info_hash20:"+string(bigBuckBunnyInfoHash[:])+"e", "1:q9:get_peers", "1:t2:zy", "1:v4:LT2H", "1:y1:q")},
		{"announce_peer query", dhtDict("1:ad2:id20:"+string(nodeID[:])+"9:info_hash20:"+string(bigBuckBunnyInfoHash[:])+"4:porti6881e5:token8:"+tok+"e", "1:q13:announce_peer", "1:t2:cd", "1:y1:q")},
		{"announce_peer query with implied port", dhtDict("1:ad2:id20:"+string(nodeID[:])+"12:implied_porti1e9:info_hash20:"+string(bigBuckBunnyInfoHash[:])+"4:porti0e5:token8:"+tok+"e", "1:q13:announce_peer", "1:t2:ce", "1:y1:q")},
		{"sample_infohashes query", dhtDict("1:ad2:id20:"+string(nodeID[:])+"6:target20:"+string(target[:])+"e", "1:q17:sample_infohashes", "1:t2:ef", "1:y1:q")},
		{"bep44 get query", dhtDict("1:ad2:id20:"+string(nodeID[:])+"6:target20:"+string(target[:])+"e", "1:q3:get", "1:t2:gh", "1:y1:q")},
		{"bep44 immutable put query with nested value", dhtDict(
			"1:ad2:id20:"+string(nodeID[:])+"5:token8:"+tok+"1:vd3:bari42eee",
			"1:q3:put", "1:t2:ij", "1:y1:q")},
		{"bep44 mutable put query", dhtDict(
			"1:ad3:casi6e2:id20:"+string(nodeID[:])+"1:k32:"+strings.Repeat("k", 32)+"4:salt64:"+strings.Repeat("a", 64)+"3:seqi7e3:sig64:"+strings.Repeat("s", 64)+"5:token8:"+tok+"1:v4:spame",
			"1:q3:put", "1:t2:ik", "1:y1:q")},
		{"ping response", dhtDict("1:rd2:id20:"+string(nodeID[:])+"e", "1:t2:ab", "1:y1:r")},
		{"find_node response with compact nodes", dhtDict(
			"1:rd2:id20:"+string(nodeID[:])+"5:nodes52:"+string(nodeID[:])+compact1+string(target[:])+compact2+"e",
			"1:t4:abcd", "1:y1:r")},
		{"get_peers response with values list", dhtDict(
			"1:rd2:id20:"+string(nodeID[:])+"5:token8:"+tok+"6:valuesl6:"+compact1+"6:"+compact2+"ee",
			"1:t2:zy", "1:y1:r")},
		{"sample_infohashes response", dhtDict(
			"1:rd2:id20:"+string(nodeID[:])+"3:numi2e7:samples40:"+samples+"8:interval1:5e",
			"1:t2:ef", "1:y1:r")},
		{"error response", dhtDict("1:eli201e12:Server Errore", "1:t2:ab", "1:y1:e")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header, err := SniffDHT(tc.payload)
			if err != nil || header == nil {
				t.Fatalf("DHT message not detected: err=%v", err)
			}
			if got := header.Protocol(); got != "bittorrent" {
				t.Fatalf("protocol = %q, want bittorrent", got)
			}
		})
	}

	t.Run("coalesced datagram after valid message", func(t *testing.T) {
		payload := append(dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:q4:ping", "1:t2:ab", "1:y1:q"), 'x', 'x')
		if header, err := SniffDHT(payload); err != nil || header == nil {
			t.Fatalf("message with trailing bytes not detected: err=%v", err)
		}
	})
}

// TestSniffDHTRejectsNonDHTBencode proves that generic bencode and KRPC
// dictionaries with wrong shapes are not classified as bittorrent.
func TestSniffDHTRejectsNonDHTBencode(t *testing.T) {
	nodeID := randomInfoHash(newMockRand(15))
	cases := []struct {
		name    string
		payload []byte
	}{
		{"generic bencode without y", dhtDict("1:ai1e4:spaml1:a2:bcee")},
		{"y wrong type", dhtDict("1:yi1ee")},
		{"y unknown value", dhtDict("1:y1:x1:t2:aae")},
		{"y longer than one char", dhtDict("1:y2:qq1:t2:aae")},
		{"unknown query name", dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:q3:foo", "1:t2:aa", "1:y1:q")},
		{"ping without node id", dhtDict("1:ade", "1:q4:ping", "1:t2:aa", "1:y1:q")},
		{"ping with short node id", dhtDict("1:ad2:id4:shrte", "1:q4:ping", "1:t2:aa", "1:y1:q")},
		{"find_node without target", dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:q9:find_node", "1:t2:aa", "1:y1:q")},
		{"get_peers without info hash", dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:q9:get_peers", "1:t2:aa", "1:y1:q")},
		{"announce_peer without token", dhtDict("1:ad2:id20:"+string(nodeID[:])+"9:info_hash20:"+string(nodeID[:])+"4:porti6881ee", "1:q13:announce_peer", "1:t2:aa", "1:y1:q")},
		{"announce_peer implied port without port field", dhtDict("1:ad2:id20:"+string(nodeID[:])+"12:implied_porti1e9:info_hash20:"+string(nodeID[:])+"5:token8:abcdefgh"+"e", "1:q13:announce_peer", "1:t2:aa", "1:y1:q")},
		{"bep44 get without target", dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:q3:get", "1:t2:aa", "1:y1:q")},
		{"bep44 get with non-integer seq", dhtDict("1:ad2:id20:"+string(nodeID[:])+"3:seq1:x6:target20:"+string(nodeID[:])+"e", "1:q3:get", "1:t2:aa", "1:y1:q")},
		{"bep44 put without token", dhtDict("1:ad2:id20:"+string(nodeID[:])+"1:v4:spame", "1:q3:put", "1:t2:aa", "1:y1:q")},
		{"bep44 mutable put without signature", dhtDict("1:ad2:id20:"+string(nodeID[:])+"1:k32:"+strings.Repeat("k", 32)+"3:seqi7e5:token8:abcdefgh1:v4:spame", "1:q3:put", "1:t2:aa", "1:y1:q")},
		{"bep44 mutable put with oversized salt", dhtDict("1:ad2:id20:"+string(nodeID[:])+"1:k32:"+strings.Repeat("k", 32)+"4:salt65:"+strings.Repeat("a", 65)+"3:seqi7e3:sig64:"+strings.Repeat("s", 64)+"5:token8:abcdefgh1:v4:spame", "1:q3:put", "1:t2:aa", "1:y1:q")},
		{"sample_infohashes without target", dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:q17:sample_infohashes", "1:t2:aa", "1:y1:q")},
		{"query without transaction id", dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:q4:ping", "1:y1:q")},
		{"query without query name", dhtDict("1:ad2:id20:"+string(nodeID[:])+"e", "1:t2:aa", "1:y1:q")},
		{"query without argument dict", dhtDict("1:q4:ping", "1:t2:aa", "1:y1:q")},
		{"response without result dict", dhtDict("1:t2:aa", "1:y1:r")},
		{"response result without node id", dhtDict("1:rd1:xi1ee", "1:t2:aa", "1:y1:r")},
		{"error without list", dhtDict("1:ei201e", "1:t2:aa", "1:y1:e")},
		{"error list too short", dhtDict("1:eli201ee", "1:t2:aa", "1:y1:e")},
		{"error list first item not int", dhtDict("1:el1:a2:bee", "1:t2:aa", "1:y1:e")},
		{"junk after dict start", []byte("deadbeef not bencode at all")},
		{"truncated dictionary", []byte("d1:ad2:id20:" + string(nodeID[:]))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if header, err := SniffDHT(tc.payload); err == nil && header != nil {
				t.Fatalf("classified as bittorrent, want rejection")
			}
		})
	}
}

// udpTrackerAnnounce builds the 98-byte BEP 15 announce request a client
// sends when it reuses a cached connection id on a new flow.
func udpTrackerAnnounce(connID uint64, txn uint32, infoHash [20]byte) []byte {
	b := make([]byte, 98)
	putUint64 := func(v uint64, off int) {
		b[off] = byte(v >> 56)
		b[off+1] = byte(v >> 48)
		b[off+2] = byte(v >> 40)
		b[off+3] = byte(v >> 32)
		b[off+4] = byte(v >> 24)
		b[off+5] = byte(v >> 16)
		b[off+6] = byte(v >> 8)
		b[off+7] = byte(v)
	}
	putUint64(connID, 0)
	binaryPutUint32(b[8:12], 1) // action announce
	binaryPutUint32(b[12:16], txn)
	copy(b[16:36], infoHash[:])
	copy(b[36:56], "-qB4530-xk2f9amqbtt3")
	binaryPutUint32(b[80:84], 2) // event started
	binaryPutUint32(b[88:92], 0x12345678)
	binaryPutUint32(b[92:96], 0xFFFFFFFF) // num_want -1
	b[96], b[97] = 0x1A, 0xE1             // port 6881
	return b
}

func binaryPutUint32(dst []byte, v uint32) {
	dst[0] = byte(v >> 24)
	dst[1] = byte(v >> 16)
	dst[2] = byte(v >> 8)
	dst[3] = byte(v)
}

// udpTrackerScrape builds a BEP 15 scrape request for two info hashes.
func udpTrackerScrape(connID uint64, txn uint32, hashes [][20]byte) []byte {
	b := make([]byte, 16+20*len(hashes))
	b[0], b[1], b[2], b[3] = 0x00, 0x00, 0x04, 0x17
	b[4], b[5], b[6], b[7] = 0x27, 0x10, 0x19, 0x80
	binaryPutUint32(b[8:12], 2)
	binaryPutUint32(b[12:16], txn)
	for i, h := range hashes {
		copy(b[16+20*i:], h[:])
	}
	return b
}

// TestSniffUDPTracker accepts only the connect request: it is the sole
// tracker message anchored by the fixed 64-bit protocol id, so it is the
// only shape safe to classify on the first datagram of a flow.
func TestSniffUDPTracker(t *testing.T) {
	t.Run("connect request", func(t *testing.T) {
		payload := udpTrackerConnect(0xDEADBEEF)
		if header, err := SniffUDPTracker(payload); err != nil || header == nil {
			t.Fatalf("connect not detected: err=%v", err)
		}
	})

	t.Run("connect request with extension bytes", func(t *testing.T) {
		payload := append(udpTrackerConnect(0xDEADBEEF), 1, 2, 3, 4)
		if header, err := SniffUDPTracker(payload); err != nil || header == nil {
			t.Fatalf("extended connect not detected: err=%v", err)
		}
	})
}

// TestSniffUDPTrackerRejectsForeignDatagrams proves no non-tracker datagram
// is classified as tracker traffic.
func TestSniffUDPTrackerRejectsForeignDatagrams(t *testing.T) {
	r := newMockRand(17)
	cases := []struct {
		name    string
		payload []byte
	}{
		{"16 bytes wrong magic", blockPayload(r, 16)},
		{"connect with announce action", func() []byte {
			b := udpTrackerConnect(1)
			binaryPutUint32(b[8:12], 1)
			return b
		}()},
		// A cached-connection-id announce or scrape carries no protocol id:
		// its only anchors are small counter values at offset 8, a shape
		// ordinary game and media datagrams reproduce constantly. These
		// genuine tracker messages are deliberately not classified.
		{"announce without connect magic", udpTrackerAnnounce(0x1234567890ABCDEF, 7, bigBuckBunnyInfoHash)},
		{"announce with extension bytes", append(udpTrackerAnnounce(0x1234567890ABCDEF, 7, bigBuckBunnyInfoHash), 1, 2, 3, 4)},
		{"scrape without connect magic", udpTrackerScrape(0x1234567890ABCDEF, 8, [][20]byte{bigBuckBunnyInfoHash, randomInfoHash(newMockRand(16))})},
		{"game datagram with sequence counter one", func() []byte {
			b := blockPayload(newMockRand(18), 100)
			binaryPutUint32(b[8:12], 1) // packet counter
			binaryPutUint32(b[80:84], 0)
			b[96], b[97] = 0x1F, 0x90
			return b
		}()},
		{"media datagram with message type two", func() []byte {
			b := blockPayload(newMockRand(19), 36)
			binaryPutUint32(b[8:12], 2) // message kind
			return b
		}()},
		{"98 bytes with unknown action", func() []byte {
			b := udpTrackerAnnounce(0x1234567890ABCDEF, 7, bigBuckBunnyInfoHash)
			binaryPutUint32(b[8:12], 5)
			return b
		}()},
		{"announce with invalid event", func() []byte {
			b := udpTrackerAnnounce(0x1234567890ABCDEF, 7, bigBuckBunnyInfoHash)
			binaryPutUint32(b[80:84], 9)
			return b
		}()},
		{"announce with zero port", func() []byte {
			b := udpTrackerAnnounce(0x1234567890ABCDEF, 7, bigBuckBunnyInfoHash)
			b[96], b[97] = 0, 0
			return b
		}()},
		{"scrape with invalid info hash framing", func() []byte {
			b := make([]byte, 20)
			binaryPutUint32(b[8:12], 2)
			return b
		}()},
		{"random datagram", blockPayload(r, 96)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if header, err := SniffUDPTracker(tc.payload); err == nil && header != nil {
				t.Fatalf("classified as bittorrent, want rejection")
			}
		})
	}
}
