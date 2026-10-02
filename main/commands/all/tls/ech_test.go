package tls

import (
	"crypto/ecdh"
	"crypto/hpke"
	gotls "crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/cryptobyte"
)

func TestValidateECHPublicName(t *testing.T) {
	for _, name := range []string{"cloudflare-ech.com", "public.example.com", "xn--bcher-kva.example", "a-b.c0"} {
		if err := validateECHPublicName(name); err != nil {
			t.Errorf("validateECHPublicName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{
		"",
		"localhost",
		"192.0.2.1",
		"2001:db8::1",
		"example.123",
		"-bad.example",
		"bad-.example",
		"a..example",
		"example.com.",
		"exa_mple.com",
		"bücher.example",
		"public.example.com:443",
		strings.Repeat(strings.Repeat("a", 60)+".", 5) + "example",
		strings.Repeat("a", 64) + ".example",
	} {
		if err := validateECHPublicName(name); err == nil {
			t.Errorf("validateECHPublicName(%q) accepted a name clients ignore", name)
		}
	}
}

func TestResolveECHConfigID(t *testing.T) {
	for _, id := range []int{0, 7, 255} {
		got, err := resolveECHConfigID(id)
		if err != nil || int(got) != id {
			t.Errorf("resolveECHConfigID(%d) = (%d, %v), want (%d, nil)", id, got, err, id)
		}
	}
	for _, id := range []int{-2, 256} {
		if _, err := resolveECHConfigID(id); err == nil {
			t.Errorf("resolveECHConfigID(%d) accepted an out-of-range ID", id)
		}
	}
	// -1 asks for a random ID; any byte is valid, so only the call is checked.
	if _, err := resolveECHConfigID(-1); err != nil {
		t.Fatalf("resolveECHConfigID(-1) = %v, want a random ID", err)
	}
}

// A generated key set must carry the requested config ID and name-length hint
// and complete a real ECH handshake between Go TLS peers.
func TestGeneratedECHKeySetCompletesHandshake(t *testing.T) {
	config, private, err := generateECHKeySet(42, "public.example.com", hpke.DHKEM(ecdh.X25519()).ID(), 64)
	if err != nil {
		t.Fatal(err)
	}
	configBytes, err := marshalBinary(config)
	if err != nil {
		t.Fatal(err)
	}
	contents := cryptobyte.String(configBytes[4:]) // version and length prefix
	var configID uint8
	if !contents.ReadUint8(&configID) || configID != 42 {
		t.Fatalf("config_id = %d, want 42", configID)
	}
	if config.MaxNameLength != 64 {
		t.Fatalf("maximum_name_length = %d, want 64", config.MaxNameLength)
	}

	var keys cryptobyte.Builder
	keys.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(private) })
	keys.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(configBytes) })
	keyBytes, err := keys.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	serverKeys, err := xraytls.ConvertToGoECHKeys(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	var list cryptobyte.Builder
	list.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(configBytes) })
	configList, err := list.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	generated, _ := cert.MustGenerate(nil, cert.CommonName("inner.example.com"), cert.DNSNames("inner.example.com", "public.example.com"))
	certificatePEM, privateKeyPEM := generated.ToPEM()
	certificate, err := gotls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	_ = clientRaw.SetDeadline(deadline)
	_ = serverRaw.SetDeadline(deadline)
	server := gotls.Server(serverRaw, &gotls.Config{
		Certificates:             []gotls.Certificate{certificate},
		EncryptedClientHelloKeys: serverKeys,
		MinVersion:               gotls.VersionTLS13,
	})
	client := gotls.Client(clientRaw, &gotls.Config{
		ServerName:                     "inner.example.com",
		InsecureSkipVerify:             true,
		EncryptedClientHelloConfigList: configList,
		MinVersion:                     gotls.VersionTLS13,
	})
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client ECH handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server ECH handshake: %v", err)
	}
	if !client.ConnectionState().ECHAccepted || !server.ConnectionState().ECHAccepted {
		t.Fatal("ECH was not accepted with the generated key set")
	}
	if got := server.ConnectionState().ServerName; got != "inner.example.com" {
		t.Fatalf("server saw inner SNI %q, want inner.example.com", got)
	}
}
