package bittorrent_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/protocol/bittorrent"
)

// The announce and scrape requests of BEP 3 and BEP 48, as clients send
// them to an HTTP tracker.
func TestSniffHTTPTracker(t *testing.T) {
	for name, request := range map[string]string{
		"qBittorrent announce":  "GET /announce?info_hash=%9a%81%3b%ef%8f%10%a1%c9%e6%1a%c4%e9%b7%07%42%cf%33%8c%2b%e2&peer_id=-qB4630-k8hj0wgej6ch&port=6881&uploaded=0&downloaded=0&left=0&corrupt=0&key=E7B3A5B1&event=started&numwant=200&compact=1&no_peer_id=1&supportcrypto=1&redundant=0 HTTP/1.1\r\nHost: tracker.example.com\r\nUser-Agent: qBittorrent/4.6.3\r\n\r\n",
		"Transmission announce": "GET /announce.php?passkey=abc&info_hash=%9a%81%3b%ef&peer_id=-TR4060-ab12cd34ef56&port=51413&uploaded=0&downloaded=0&left=1&numwant=80&key=1a2b3c&compact=1&supportcrypto=1&event=started HTTP/1.1\r\nHost: t.example.org\r\n\r\n",
		"scrape":                "GET /scrape?info_hash=%9a%81%3b%ef HTTP/1.1\r\nHost: tracker.example.com\r\n\r\n",
		"request line only":     "GET /announce?info_hash=x&peer_id=y",
		// Announce paths of real trackers that do not say announce.
		"RuTracker":           "GET /ann?pk=0123456789abcdef&info_hash=%9a%81%3b%ef&peer_id=-qB4630-k8hj0wgej6ch&port=6881&uploaded=0&downloaded=0&left=0&event=started&compact=1 HTTP/1.1\r\nHost: bt4.t-ru.org\r\n\r\n",
		"passkey in the path": "GET /0123456789abcdef/announce?info_hash=%9a%81&peer_id=-TR4060-ab12cd34ef56 HTTP/1.1\r\nHost: t.example.org\r\n\r\n",
		"TorrentPier":         "GET /bt/announce.php?uk=abc&info_hash=%9a%81&peer_id=-qB4630-k8hj0wgej6ch HTTP/1.1\r\nHost: bt.example.org\r\n\r\n",
		"root path":           "GET /?info_hash=%9a%81&peer_id=-qB4630-k8hj0wgej6ch&port=6881 HTTP/1.1\r\nHost: t.example.org\r\n\r\n",
		"scrape.php":          "GET /scrape.php?info_hash=%9a%81 HTTP/1.1\r\nHost: t.example.org\r\n\r\n",
		"escaped names":       "GET /announce?info%5Fhash=%9a%81&peer%5fid=-qB4630-k8hj0wgej6ch HTTP/1.1\r\nHost: t.example.org\r\n\r\n",
	} {
		if _, err := SniffHTTPTracker([]byte(request)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSniffHTTPTrackerRejects(t *testing.T) {
	for name, request := range map[string]string{
		"page":                         "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"info_hash alone":              "GET /torrent?info_hash=abc HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"peer_id alone":                "GET /api?peer_id=abc HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"words in a header":            "GET / HTTP/1.1\r\nHost: example.com\r\nX-Note: info_hash= peer_id=\r\n\r\n",
		"words in a body":              "POST /announce HTTP/1.1\r\nHost: example.com\r\nContent-Length: 30\r\n\r\ninfo_hash=1&peer_id=2&port=3",
		"response":                     "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\ninfo_hash=1&peer_id=2",
		"words on the second line":     "GET /a HTTP/1.1\nGET /announce?info_hash=1&peer_id=2 HTTP/1.1\r\n",
		"TLS ClientHello":              "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
		"lower-case get is no request": "get /announce?info_hash=1&peer_id=2 HTTP/1.1\r\n",
		"names in the path":            "GET /docs/info_hash=x/peer_id=y HTTP/1.1\r\n",
		"names inside other names":     "GET /api?previous_info_hash=abc&last_peer_id=def HTTP/1.1\r\n",
		"scrape in a parameter":        "GET /search?info_hash=abc&q=/scrape? HTTP/1.1\r\n",
		"announce without peer_id":     "GET /announce?info_hash=abc HTTP/1.1\r\n",
		"scrape in a directory":        "GET /scrape/page?info_hash=abc HTTP/1.1\r\n",
	} {
		if _, err := SniffHTTPTracker([]byte(request)); err == nil {
			t.Errorf("%s taken for a tracker request", name)
		}
	}
	for _, prefix := range []string{"", "G", "GET", "GET "} {
		if _, err := SniffHTTPTracker([]byte(prefix)); err != common.ErrNoClue {
			t.Errorf("%q: %v, want no clue yet", prefix, err)
		}
	}
}

func TestSniffLSD(t *testing.T) {
	lsd := "BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 6881\r\nInfohash: 9a813bef8f10a1c9e61ac4e9b70742cf338c2be2\r\ncookie: 1a2b\r\n\r\n\r\n"
	if _, err := SniffLSD([]byte(lsd)); err != nil {
		t.Fatalf("LSD announce: %v", err)
	}
	for name, datagram := range map[string]string{
		"SSDP search":    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
		"SSDP notify":    "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n",
		"words inside":   "NOTIFY * HTTP/1.1\r\nX: BT-SEARCH * HTTP/1.1\r\n\r\n",
		"other protocol": "BT-SEARCH * HTTP/1.0\r\nHost: x\r\n\r\n",
	} {
		if _, err := SniffLSD([]byte(datagram)); err == nil {
			t.Errorf("%s taken for LSD", name)
		}
	}
}

// A datagram too short for the LSD request line is turned down as soon as
// its bytes differ, and waits for more only while they match.
func TestSniffLSDShortDatagrams(t *testing.T) {
	for _, size := range []int{1, 20, 21} {
		if _, err := SniffLSD(make([]byte, size)); err == common.ErrNoClue {
			t.Errorf("%d zero bytes: no clue, want a rejection", size)
		}
	}
	if _, err := SniffLSD([]byte("BT-SEARCH * HTTP/1.1")); err != common.ErrNoClue {
		t.Errorf("start of an LSD request: %v, want no clue yet", err)
	}
}

// utpData builds a uTP ST_DATA with the given extension chain and data.
func utpData(exts []byte, firstExt byte, data []byte) []byte {
	b := []byte{0x01, firstExt, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x13, 0x88, 0x00, 0x10, 0x00, 0x00, 0x23, 0xc7, 0x5a, 0x01}
	b = append(b, exts...)
	return append(b, data...)
}

var handshake = append([]byte("\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x05"), make([]byte, 40)...)

// A uTP flow sniffed after its SYN opens with the handshake in its first
// ST_DATA.
func TestSniffUTPHandshake(t *testing.T) {
	if _, err := SniffUTP(utpData(nil, 0, handshake)); err != nil {
		t.Fatalf("ST_DATA with the handshake: %v", err)
	}
	sack := []byte{0, 4, 0xff, 0x00, 0x00, 0x00}
	if _, err := SniffUTP(utpData(sack, 1, handshake)); err != nil {
		t.Fatalf("ST_DATA with a selective ack, then the handshake: %v", err)
	}
	for name, packet := range map[string][]byte{
		"ST_DATA with other data":            utpData(nil, 0, append([]byte("\x00\x00\x00\x0d\x06"), make([]byte, 40)...)),
		"handshake not where the data opens": utpData(nil, 0, append([]byte{0}, handshake...)),
		"handshake past a broken extension":  utpData([]byte{0, 3, 1, 2, 3}, 1, handshake),
		"ST_STATE with the handshake":        append([]byte{0x21}, utpData(nil, 0, handshake)[1:]...),
	} {
		if _, err := SniffUTP(packet); err == nil {
			t.Errorf("%s taken for uTP", name)
		}
	}
}
