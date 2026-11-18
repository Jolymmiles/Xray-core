package stun_test

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/common/protocol/stun"
)

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rfc5769Request is the sample request of RFC 5769, section 2.1: a binding
// request of ICE with SOFTWARE, PRIORITY, ICE-CONTROLLED, USERNAME,
// MESSAGE-INTEGRITY and FINGERPRINT.
const rfc5769Request = `
	00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
	80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74
	00 24 00 04 6e 00 01 ff
	80 29 00 08 93 2f f9 b1 51 26 3b 36
	00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20
	00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2
	80 28 00 04 e5 7a 3b cf`

// message builds a STUN message of type typ with the given attributes, each
// a type and a value, padded as the RFC pads them.
func message(typ uint16, attrs ...[]byte) []byte {
	var body []byte
	for i := 0; i+1 < len(attrs); i += 2 {
		v := attrs[i+1]
		body = binary.BigEndian.AppendUint16(body, binary.BigEndian.Uint16(attrs[i]))
		body = binary.BigEndian.AppendUint16(body, uint16(len(v)))
		body = append(body, v...)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
	}
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	b = binary.BigEndian.AppendUint32(b, 0x2112A442)
	b = append(b, "transaction1"...)
	return append(b, body...)
}

func attr(t uint16) []byte { return binary.BigEndian.AppendUint16(nil, t) }

// TestRFC5769RequestIsTranscribed checks the sample by its own FINGERPRINT:
// CRC-32 of the message before it, XOR 0x5354554e.
func TestRFC5769RequestIsTranscribed(t *testing.T) {
	b := decode(t, rfc5769Request)
	want := binary.BigEndian.Uint32(b[len(b)-4:])
	if got := crc32.ChecksumIEEE(b[:len(b)-8]) ^ 0x5354554e; got != want {
		t.Fatalf("FINGERPRINT %08x, the message gives %08x", want, got)
	}
}

func TestSniffSTUN(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"RFC 5769 binding request", decode(t, rfc5769Request)},
		{"binding request without attributes", message(0x0001)},
		{"binding success response with XOR-MAPPED-ADDRESS", message(0x0101, attr(0x0020), decode(t, "00 01 a1 47 e1 12 a6 43"))},
		{"TURN allocate request with REQUESTED-TRANSPORT", message(0x0003, attr(0x0019), []byte{17, 0, 0, 0})},
		{"TURN data indication", message(0x0017, attr(0x0012), decode(t, "00 01 a1 47 e1 12 a6 43"), attr(0x0013), []byte("media"))},
		{"WhatsApp call type 0x0801", message(0x0801, attr(0x4000), []byte("whatsapp"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if h, err := SniffSTUN(c.b); err != nil || h.Protocol() != "stun" {
				t.Fatalf("SniffSTUN: %v", err)
			}
			if _, err := SniffSTUNDatagram(c.b); err != nil {
				t.Fatalf("SniffSTUNDatagram: %v", err)
			}
			// A stream may carry more after the message.
			if _, err := SniffSTUN(append(c.b, message(0x0001)...)); err != nil {
				t.Fatalf("SniffSTUN with a message after it: %v", err)
			}
		})
	}
}

// TestSniffSTUNStreamWaits is a STUN message over TCP read in pieces: once
// the cookie is in, the sniffer waits for the rest; before, it has no clue.
func TestSniffSTUNStreamWaits(t *testing.T) {
	b := decode(t, rfc5769Request)
	for n := 0; n < len(b); n++ {
		_, err := SniffSTUN(b[:n])
		want := protocol.ErrProtoNeedMoreData
		if n < 8 {
			want = common.ErrNoClue
		}
		if err != want {
			t.Fatalf("%d of %d bytes: %v, want %v", n, len(b), err, want)
		}
	}
}

func TestSniffSTUNRejects(t *testing.T) {
	good := decode(t, rfc5769Request)
	classic := append([]byte(nil), good...)
	copy(classic[4:8], "\xb7\xe7\xa7\x02") // RFC 3489: no cookie, all transaction id
	topBits := append([]byte(nil), good...)
	topBits[0] |= 0x40
	oddLength := message(0x0001, attr(0x8022), []byte("abc"))
	oddLength[3]--
	overrun := message(0x0001, attr(0x8022), []byte("abcd"))
	overrun[23] = 8 // the attribute says 8 bytes where the message has 4

	cases := []struct {
		name string
		b    []byte
	}{
		{"classic STUN without the cookie", classic},
		{"first two bits set", topBits},
		{"length not a multiple of 4", oddLength},
		{"attribute past the message", overrun},
		{"DNS query", decode(t, "41 00 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01")},
		{"uTP ST_SYN", decode(t, "41 00 30 39 00 00 00 01 00 00 00 00 00 10 00 00 00 01 00 00")},
		{"DHT ping", []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")},
		{"UDP tracker connect", decode(t, "00 00 04 17 27 10 19 80 00 00 00 00 12 34 56 78")},
		{"zeros", make([]byte, 64)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := SniffSTUN(c.b); err == nil {
				t.Fatal("SniffSTUN took it for STUN")
			}
			if _, err := SniffSTUNDatagram(c.b); err == nil {
				t.Fatal("SniffSTUNDatagram took it for STUN")
			}
		})
	}
}

// TestSniffSTUNDatagramIsWhole is a datagram with bytes past the message, or
// short of it: over UDP a STUN message is the whole datagram.
func TestSniffSTUNDatagramIsWhole(t *testing.T) {
	b := decode(t, rfc5769Request)
	for _, d := range [][]byte{append(b, 0, 0, 0, 0), b[:len(b)-4], b[:12]} {
		if _, err := SniffSTUNDatagram(d); err == nil {
			t.Fatalf("a datagram of %d bytes taken for a message of %d", len(d), len(b))
		}
	}
}

// TestSniffSTUNRejectsOtherSniffersCorpus runs the QUIC and TLS first flights
// the other sniffers are tested with: none is STUN.
func TestSniffSTUNRejectsOtherSniffersCorpus(t *testing.T) {
	for _, dir := range []string{"../quic/testdata", "../tls/testdata"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".bin") {
				continue
			}
			b, err := os.ReadFile(dir + "/" + e.Name())
			if err != nil {
				t.Fatal(err)
			}
			n++
			if _, err := SniffSTUN(b); err == nil {
				t.Errorf("%s/%s taken for STUN", dir, e.Name())
			}
			if _, err := SniffSTUNDatagram(b); err == nil {
				t.Errorf("%s/%s taken for a STUN datagram", dir, e.Name())
			}
		}
		if n == 0 {
			t.Fatalf("no corpus in %s", dir)
		}
	}
}

func FuzzSniffSTUN(f *testing.F) {
	f.Add(decode(&testing.T{}, rfc5769Request))
	f.Add(message(0x0001))
	// A datagram may be longer than the most a stream shows a sniffer.
	f.Add(message(0x0001, attr(0x8022), make([]byte, MaxMessageLen-20)))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, streamErr := SniffSTUN(b)
		if _, err := SniffSTUNDatagram(b); err == nil && len(b) <= MaxMessageLen && streamErr != nil {
			t.Fatalf("a whole datagram taken, the same bytes as a stream not: %v", streamErr)
		}
	})
}

// turnedDown reports whether err ends the sniff: neither "no clue yet" nor
// "need more data".
func turnedDown(err error) bool {
	return err != nil && err != common.ErrNoClue && err != protocol.ErrProtoNeedMoreData
}

// A message longer than the dispatcher shows a sniffer (MaxMessageLen) is
// turned down at once: waiting for it would keep the server reading, and
// caching, a client's upload for the whole sniff budget.
func TestSniffSTUNRejectsWhatTheCacheCannotShow(t *testing.T) {
	for _, length := range []int{0xfffc, 0x7ff0, MaxMessageLen - 20 + 4} {
		header := []byte{0x00, 0x01, byte(length >> 8), byte(length), 0x21, 0x12, 0xa4, 0x42}
		if _, err := SniffSTUN(header); !turnedDown(err) {
			t.Errorf("a header for %d bytes: %v, want it turned down", 20+length, err)
		}
	}
	whole := message(0x0001, attr(0x8022), make([]byte, MaxMessageLen-20-4))
	if len(whole) != MaxMessageLen {
		t.Fatalf("test message of %d bytes", len(whole))
	}
	if _, err := SniffSTUN(whole); err != nil {
		t.Fatalf("a whole message of MaxMessageLen bytes: %v", err)
	}
	// The RFC 4571 length counts towards what the cache shows.
	frame := func(m []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(m))), m...) }
	if _, err := SniffSTUN(frame(whole)[:10]); !turnedDown(err) {
		t.Errorf("an ICE-TCP frame of %d bytes: %v, want it turned down", 2+len(whole), err)
	}
	if fits := frame(message(0x0001, attr(0x8022), make([]byte, MaxMessageLen-20-4-4))); len(fits) > MaxMessageLen {
		t.Fatalf("test frame of %d bytes", len(fits))
	} else if _, err := SniffSTUN(fits); err != nil {
		t.Errorf("an ICE-TCP frame of %d bytes: %v", len(fits), err)
	}
}

// ICE-TCP sends each STUN message after the 2-byte length of RFC 4571 (RFC
// 6544, section 7.1); the length must be that of the message.
func TestSniffSTUNFramedForICETCP(t *testing.T) {
	m := decode(t, rfc5769Request)
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(m)))
	framed = append(framed, m...)
	if _, err := SniffSTUN(framed); err != nil {
		t.Fatalf("an ICE-TCP binding request: %v", err)
	}
	for n := 0; n < len(framed); n++ {
		want := protocol.ErrProtoNeedMoreData
		if n < 10 {
			want = common.ErrNoClue
		}
		if _, err := SniffSTUN(framed[:n]); err != want {
			t.Fatalf("%d of %d framed bytes: %v, want %v", n, len(framed), err, want)
		}
	}
	wrong := append([]byte(nil), framed...)
	wrong[1] += 4
	if _, err := SniffSTUN(wrong); !turnedDown(err) {
		t.Fatalf("a frame whose length is not the message's: %v, want it turned down", err)
	}
	if _, err := SniffSTUNDatagram(framed); err == nil {
		t.Fatal("a framed message taken for a STUN datagram: UDP has no framing")
	}
}

// Each rule of the header and the attributes turns down a message on its own.
func TestSniffSTUNRulesOneByOne(t *testing.T) {
	oddLength := message(0x0001, attr(0x8022), []byte("abc"))
	oddLength[3]--
	if _, err := SniffSTUN(oddLength[:12]); !turnedDown(err) {
		t.Errorf("a header with a length not a multiple of 4: %v, want it turned down", err)
	}
	for n := 0; n < 8; n++ {
		if _, err := SniffSTUNDatagram(decode(t, rfc5769Request)[:n]); !turnedDown(err) {
			t.Errorf("a datagram of %d bytes: %v, want it turned down", n, err)
		}
	}
}
