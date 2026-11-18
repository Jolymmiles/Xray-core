package tls

import (
	"bytes"
	gotls "crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/transport/internet/tls/hellotest"
)

// firefoxFixture reads a ClientHello record captured from Firefox 156.0.1,
// see testdata/firefox/README.md.
func firefoxFixture(t *testing.T, name string) []byte {
	t.Helper()
	text, err := os.ReadFile("testdata/firefox/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	record, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// firefoxHello builds the ClientHello Xray sends to serverName with the
// firefox fingerprint and session in the uTLS session cache, nil for none.
func firefoxHello(t *testing.T, serverName string, session *utls.ClientSessionState) []byte {
	t.Helper()
	config := &utls.Config{ServerName: serverName, InsecureSkipVerify: true}
	if session != nil {
		config.ClientSessionCache = utls.NewLRUClientSessionCache(1)
		config.ClientSessionCache.Put(serverName, session)
	}
	uConn, err := newUClient(&hellotest.Capture{}, config, utls.HelloFirefox_Auto, clientSessionResumption{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return uConn.HandshakeState.Hello.Raw
}

// TestFirefoxClientHelloFollowsCaptures compares the firefox ClientHello with
// Firefox 156.0.1's for the same server name and the same ticket size: the
// extensions in order, the length of each, the record length, and every body
// that is not a key, a ticket or the GREASE ECH's random fields. The fixtures
// sit on both sides of the server name length where the GREASE ECH grows
// (107 and 108 bytes), and offer a TLS 1.3 and a TLS 1.2 ticket.
func TestFirefoxClientHelloFollowsCaptures(t *testing.T) {
	const (
		sessionTicket = 35
		preSharedKey  = 41
		keyShare      = 51
		ech           = 65037
	)
	for _, fixture := range []string{
		"fresh-name107", "fresh-name108", "tls13-ticket-name6", "tls13-ticket-name108", "tls12-ticket-name6",
	} {
		t.Run(fixture, func(t *testing.T) {
			record := firefoxFixture(t, fixture)
			want := helloExtensions(t, record)
			serverName := string(helloExtension{id: 0}.of(want)[5:])

			var session *utls.ClientSessionState
			if psk := (helloExtension{id: preSharedKey}).of(want); psk != nil {
				session = sessionOf(t, gotls.VersionTLS13, int(binary.BigEndian.Uint16(psk[2:])))
			} else if ticket := (helloExtension{id: sessionTicket}).of(want); len(ticket) != 0 {
				session = sessionOf(t, gotls.VersionTLS12, len(ticket))
			}
			hello := firefoxHello(t, serverName, session)
			got := helloExtensions(t, hello)

			ids := func(extensions []helloExtension) (ids []uint16) {
				for _, extension := range extensions {
					ids = append(ids, extension.id)
				}
				return ids
			}
			if !slices.Equal(ids(got), ids(want)) {
				t.Fatalf("extensions\n got: %v\nwant: %v", ids(got), ids(want))
			}
			for i := range want {
				if len(got[i].body) != len(want[i].body) {
					t.Errorf("extension %d is %d bytes, want %d", want[i].id, len(got[i].body), len(want[i].body))
				}
				switch want[i].id {
				case keyShare, preSharedKey, ech:
					continue
				case sessionTicket:
					if len(want[i].body) != 0 {
						continue
					}
				}
				if !bytes.Equal(got[i].body, want[i].body) {
					t.Errorf("extension %d\n got: %x\nwant: %x", want[i].id, got[i].body, want[i].body)
				}
			}
			if len(hello)+5 != len(record) {
				t.Errorf("record of %d bytes, want %d", len(hello)+5, len(record))
			}
		})
	}
}

// TestFirefoxGREASEECHFields pins what the GREASE ECH of firefox holds beside
// its length: the outer type, HKDF-SHA256 with AES-128-GCM or
// ChaCha20-Poly1305, and a 32-byte encapsulated key that is random bytes. An
// X25519 public key, which uTLS generates by default, never has the top bit
// of its last byte set, and Firefox's has it in half of its hellos.
func TestFirefoxGREASEECHFields(t *testing.T) {
	topBit := map[bool]int{}
	aeads := map[uint16]int{}
	const hellos = 64
	for range hellos {
		body := helloExtension{id: 65037}.of(helloExtensions(t, firefoxHello(t, "example.com", nil)))
		if len(body) != 282 {
			t.Fatalf("GREASE ECH of %d bytes, want 282", len(body))
		}
		if body[0] != 0 || binary.BigEndian.Uint16(body[1:]) != 1 || binary.BigEndian.Uint16(body[6:]) != 32 {
			t.Fatalf("GREASE ECH starts %x", body[:8])
		}
		aeads[binary.BigEndian.Uint16(body[3:])]++
		topBit[body[8+31]&0x80 != 0]++
	}
	if topBit[true] == 0 || topBit[false] == 0 {
		t.Errorf("top bit of the encapsulated key's last byte: set in %d of %d hellos", topBit[true], hellos)
	}
	if len(aeads) != 2 || aeads[1] == 0 || aeads[3] == 0 {
		t.Errorf("GREASE ECH AEADs %v, want both 1 and 3", aeads)
	}
}

// TestFirefoxClientHelloOnlyWhereMeasured pins the reach of the model: the
// firefox aliases and a host name. An IP address sends no server_name, and
// the older presets were not measured; both keep their templates.
func TestFirefoxClientHelloOnlyWhereMeasured(t *testing.T) {
	for name, want := range map[string]bool{
		"example.com": true, "example.com.": true, "192.0.2.1": false, "[2001:db8::1]": false, "": false,
	} {
		if got := BuildsFirefoxClientHello(utls.HelloFirefox_Auto, name); got != want {
			t.Errorf("firefox to %q: modelled = %v, want %v", name, got, want)
		}
	}
	for name, id := range map[string]utls.ClientHelloID{
		"hellofirefox_148": utls.HelloFirefox_148, "hellofirefox_120": utls.HelloFirefox_120, "chrome": utls.HelloChrome_Auto,
	} {
		if BuildsFirefoxClientHello(id, "example.com") {
			t.Errorf("%s is built as Firefox 156", name)
		}
	}
	// A trailing dot is not sent, so it does not count.
	if a, b := firefoxHello(t, strings.Repeat("a", 60)+"."+strings.Repeat("b", 47), nil), firefoxHello(t, strings.Repeat("a", 60)+"."+strings.Repeat("b", 47)+".", nil); len(a) != len(b) {
		t.Errorf("a trailing dot changed the hello from %d to %d bytes", len(a), len(b))
	}
}

// TestFirefoxDeclinedTicketLeavesFirstHello covers a ticket uTLS refuses to
// offer, here one whose use-by time has passed. The hello must be that of a
// first connection: session_ticket is back and the GREASE ECH is not sized
// for a pre_shared_key that is not there.
func TestFirefoxDeclinedTicketLeavesFirstHello(t *testing.T) {
	session := sessionOf(t, gotls.VersionTLS13, 224)
	session.SetUseBy(uint64(time.Now().Add(-time.Hour).Unix()))
	got := helloExtensions(t, firefoxHello(t, "example.com", session))
	want := helloExtensions(t, firefoxHello(t, "example.com", nil))
	if len(got) != len(want) {
		t.Fatalf("%d extensions, want %d as in a first hello", len(got), len(want))
	}
	for i := range want {
		if got[i].id != want[i].id || len(got[i].body) != len(want[i].body) {
			t.Errorf("extension %d of %d bytes, want %d of %d bytes", got[i].id, len(got[i].body), want[i].id, len(want[i].body))
		}
	}
}

// TestFirefoxGREASEECHCountsTheTicketItOffers ties the size of the GREASE ECH
// to the pre_shared_key the same hello carries, over server names on both
// sides of NSS's padding, ticket sizes that land on both sides of a 32-byte
// step, and both binder lengths. A size computed for another ticket than the
// one uTLS writes would show here.
func TestFirefoxGREASEECHCountsTheTicketItOffers(t *testing.T) {
	session := sessionOf(t, gotls.VersionTLS13, 0)
	for _, suite := range []uint16{utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384} {
		session.SetCipherSuite(suite)
		for _, nameLen := range []int{11, 100, 107, 108, 140, 200} {
			name := strings.Repeat("a", 40) + "." + strings.Repeat("b", 40)
			for len(name) < nameLen-5 {
				name += "." + strings.Repeat("c", min(40, nameLen-5-len(name)-1))
			}
			name = name[:min(len(name), nameLen-5)] + ".test"
			if len(name) != nameLen {
				t.Fatalf("server name of %d bytes, want %d", len(name), nameLen)
			}
			for _, ticketLen := range []int{32, 105, 113, 121, 224, 336} {
				session.SetSessionTicket(make([]byte, ticketLen))
				extensions := helloExtensions(t, firefoxHello(t, name, session))
				psk := helloExtension{id: 41}.of(extensions)
				if psk == nil || extensions[len(extensions)-1].id != 41 {
					t.Fatalf("suite %#04x, name %d, ticket %d: no pre_shared_key in last place", suite, nameLen, ticketLen)
				}
				if identity := int(binary.BigEndian.Uint16(psk[2:])); identity != ticketLen {
					t.Fatalf("offered an identity of %d bytes, want %d", identity, ticketLen)
				}
				want := 42 + (117+max(nameLen, 100)+len(psk)+4+31)/32*32 + 16
				if got := len(helloExtension{id: 65037}.of(extensions)); got != want {
					t.Errorf("suite %#04x, name %d, pre_shared_key %d: GREASE ECH of %d bytes, want %d",
						suite, nameLen, len(psk)+4, got, want)
				}
			}
		}
	}
}
