package mtproxy

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestMiddleCryptoKeyDerivationIPv4Vector(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(32 + i)
	}
	var serverNonce, clientNonce [16]byte
	for i := range serverNonce {
		serverNonce[i] = byte(i)
		clientNonce[i] = byte(16 + i)
	}
	endpoints := MiddleEndpoints{
		Server: netip.MustParseAddrPort("149.154.167.40:54321"),
		Client: netip.MustParseAddrPort("203.0.113.9:443"),
	}
	keys, err := DeriveMiddleKeyData(true, secret, serverNonce, clientNonce, 1_700_000_000, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{"write key", keys.WriteKey[:], "6c8b5a427999840bbb397cd4b05bc797eb58ffd3388e78246a6bbc300c4a2b5f"},
		{"write IV", keys.WriteIV[:], "c0908bcd22d968280307ed695aef4696"},
		{"read key", keys.ReadKey[:], "913b317aab9d24dc237728a6494ba5a24bf96775ad603ad0f858f49c6e09208a"},
		{"read IV", keys.ReadIV[:], "03960c18001634e9473e56812be40520"},
	}
	for _, test := range tests {
		if !bytes.Equal(test.got, mustHex(t, test.want)) {
			t.Fatalf("%s = %x, want %s", test.name, test.got, test.want)
		}
	}

	serverKeys, err := DeriveMiddleKeyData(false, secret, serverNonce, clientNonce, 1_700_000_000, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	if keys.WriteKey != serverKeys.ReadKey || keys.WriteIV != serverKeys.ReadIV || keys.ReadKey != serverKeys.WriteKey || keys.ReadIV != serverKeys.WriteIV {
		t.Fatal("client and server directional key data do not mirror")
	}
}

func TestMiddleCryptoCBCContinuousBlocks(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, 32)
	var serverNonce, clientNonce [16]byte
	copy(serverNonce[:], bytes.Repeat([]byte{1}, 16))
	copy(clientNonce[:], bytes.Repeat([]byte{2}, 16))
	endpoints := MiddleEndpoints{Server: netip.MustParseAddrPort("149.154.167.40:443"), Client: netip.MustParseAddrPort("203.0.113.9:50000")}
	clientKeys, _ := DeriveMiddleKeyData(true, secret, serverNonce, clientNonce, 123, endpoints)
	serverKeys, _ := DeriveMiddleKeyData(false, secret, serverNonce, clientNonce, 123, endpoints)
	client, err := NewMiddleCBC(clientKeys)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewMiddleCBC(serverKeys)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("0123456789abcdefABCDEFGHIJKLMNOP")
	ciphertext := make([]byte, len(plaintext))
	if err := client.Encrypt(ciphertext[:16], plaintext[:16]); err != nil {
		t.Fatal(err)
	}
	if err := client.Encrypt(ciphertext[16:], plaintext[16:]); err != nil {
		t.Fatal(err)
	}
	decoded := make([]byte, len(plaintext))
	if err := server.Decrypt(decoded, ciphertext); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("decoded = %q, want %q", decoded, plaintext)
	}
	if err := client.Encrypt(make([]byte, 1), []byte{1}); err == nil {
		t.Fatal("Encrypt accepted a partial block")
	}
}

func TestMiddleHandshakeNoncePacketRoundTripAndValidation(t *testing.T) {
	secret := bytes.Repeat([]byte{0x44}, 32)
	var nonce [16]byte
	copy(nonce[:], bytes.Repeat([]byte{0x33}, 16))
	packet, err := NewMiddleClientNonce(secret, 1_700_000_000, nonce)
	if err != nil {
		t.Fatal(err)
	}
	encoded := EncodeMiddleNonce(packet)
	decoded, err := DecodeMiddleNonce(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != packet {
		t.Fatalf("decoded nonce = %+v, want %+v", decoded, packet)
	}
	if err := ValidateMiddleServerNonce(decoded, secret, 1_700_000_020); err != nil {
		t.Fatalf("ValidateMiddleServerNonce() error = %v", err)
	}
	decoded.Timestamp -= 31
	if err := ValidateMiddleServerNonce(decoded, secret, 1_700_000_020); err == nil {
		t.Fatal("stale Middle-End nonce accepted")
	}
	decoded = packet
	decoded.KeySelector++
	if err := ValidateMiddleServerNonce(decoded, secret, 1_700_000_000); err == nil {
		t.Fatal("wrong key selector accepted")
	}
}

func TestMiddleCryptoRejectsInvalidInputs(t *testing.T) {
	var nonce [16]byte
	valid := MiddleEndpoints{Server: netip.MustParseAddrPort("149.154.167.40:443"), Client: netip.MustParseAddrPort("203.0.113.9:50000")}
	if _, err := DeriveMiddleKeyData(true, []byte("short"), nonce, nonce, 1, valid); err == nil {
		t.Fatal("short secret accepted")
	}
	mixed := MiddleEndpoints{Server: netip.MustParseAddrPort("149.154.167.40:443"), Client: netip.MustParseAddrPort("[2001:db8::1]:50000")}
	if _, err := DeriveMiddleKeyData(true, bytes.Repeat([]byte{1}, 32), nonce, nonce, 1, mixed); err == nil {
		t.Fatal("mixed address families accepted")
	}
}
