package tls

import (
	gotls "crypto/tls"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/transport/internet/tls/hellotest"
)

// testECHConfigList is a list of one ECHConfig of draft version fe0d: config
// id, DHKEM(X25519), a public key, HKDF-SHA256 with AES-128-GCM, no name
// limit, a public name.
func testECHConfigList() []byte {
	contents := append([]byte{7, 0, 0x20, 0, 32}, make([]byte, 32)...)
	contents[5] = 9 // an X25519 public key that is not the zero point
	contents = append(contents, 0, 4, 0, 1, 0, 1, 0, 14)
	contents = append(contents, "public.example"...)
	contents = append(contents, 0, 0)
	echConfig := append([]byte{0xfe, 0x0d, 0, byte(len(contents))}, contents...)
	return append([]byte{0, byte(len(echConfig))}, echConfig...)
}

// TestRealECHOffersNoTicket covers a config with a real ECH config list and a
// ticket in the cache. uTLS cannot put the ticket into the inner hello and
// refuses to build a hello that offers one, which failed the dial; the hello
// is built without it.
func TestRealECHOffersNoTicket(t *testing.T) {
	list := testECHConfigList()
	session := sessionOf(t, gotls.VersionTLS13, 224)
	for name, id := range map[string]utls.ClientHelloID{
		"chrome": utls.HelloChrome_Auto, "edge": utls.HelloEdge_Auto,
		"firefox": utls.HelloFirefox_Auto, "hellofirefox_120": utls.HelloFirefox_120,
	} {
		t.Run(name, func(t *testing.T) {
			resumption := clientSessionResumption{configured: true, source: gotls.NewLRUClientSessionCache(1)}
			resumption.sessionCache(id).Put("inner.example", session)
			config := &utls.Config{
				ServerName: "inner.example", InsecureSkipVerify: true, OmitEmptyPsk: true,
				EncryptedClientHelloConfigList: list,
			}
			uConn, err := newUClient(&hellotest.Capture{}, config, id, resumption, nil)
			if err != nil {
				t.Fatalf("the ClientHello was not built: %v", err)
			}
			if psk := (helloExtension{id: 41}).of(helloExtensions(t, uConn.HandshakeState.Hello.Raw)); psk != nil {
				t.Fatal("the outer ClientHello offers a ticket")
			}
		})
	}
}

// TestRealECHKeepsGoClientSessionCache pins the one client the rule above
// leaves alone: HelloGolang is Go's own client, which puts a ticket into the
// inner hello, so it keeps the session cache its caller gave it.
func TestRealECHKeepsGoClientSessionCache(t *testing.T) {
	for name, want := range map[string]bool{"hellogolang": true, "chrome": false} {
		id := utls.HelloChrome_Auto
		if want {
			id = utls.HelloGolang
		}
		config := &utls.Config{
			ServerName: "inner.example", InsecureSkipVerify: true,
			ClientSessionCache:             utls.NewLRUClientSessionCache(1),
			EncryptedClientHelloConfigList: testECHConfigList(),
		}
		if _, err := newUClient(&hellotest.Capture{}, config, id, clientSessionResumption{}, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if kept := config.ClientSessionCache != nil; kept != want {
			t.Errorf("%s with real ECH keeps its session cache: %v, want %v", name, kept, want)
		}
	}
}
