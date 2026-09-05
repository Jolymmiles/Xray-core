package mtproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func testSecret(value byte) [16]byte {
	var secret [16]byte
	for i := range secret {
		secret[i] = value + byte(i)
	}
	return secret
}

func testDirectionalMaterial(header *[obfuscatedHeaderSize]byte, secret [16]byte, reverse bool) ([32]byte, [16]byte) {
	var seed [48]byte
	if reverse {
		for i := 0; i < len(seed); i++ {
			seed[i] = header[55-i]
		}
	} else {
		copy(seed[:], header[8:56])
	}

	var input [48]byte
	copy(input[:32], seed[:32])
	copy(input[32:], secret[:])
	key := sha256.Sum256(input[:])

	var iv [16]byte
	copy(iv[:], seed[32:])
	return key, iv
}

func testCTR(t *testing.T, key [32]byte, iv [16]byte) cipher.Stream {
	t.Helper()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	return cipher.NewCTR(block, iv[:])
}

func buildClientHeader(t *testing.T, secret [16]byte, mode FrameMode, dcID int16) ([obfuscatedHeaderSize]byte, cipher.Stream, cipher.Stream) {
	t.Helper()

	var plain [obfuscatedHeaderSize]byte
	for i := range plain {
		plain[i] = byte(0x31 + i*7)
	}
	binary.LittleEndian.PutUint32(plain[56:60], uint32(mode))
	binary.LittleEndian.PutUint16(plain[60:62], uint16(dcID))

	readKey, readIV := testDirectionalMaterial(&plain, secret, false)
	clientEncrypt := testCTR(t, readKey, readIV)
	encrypted := plain
	clientEncrypt.XORKeyStream(encrypted[:], encrypted[:])

	wire := plain
	copy(wire[56:], encrypted[56:])

	writeKey, writeIV := testDirectionalMaterial(&plain, secret, true)
	clientDecrypt := testCTR(t, writeKey, writeIV)
	return wire, clientEncrypt, clientDecrypt
}

func TestObfuscatedHandshakeDirectionalStreams(t *testing.T) {
	first := testSecret(0x10)
	matching := testSecret(0x40)
	wire, clientEncrypt, clientDecrypt := buildClientHeader(t, matching, FrameModePaddedIntermediate, -3)

	state, err := AcceptObfuscatedHeader(wire, [][16]byte{first, matching})
	if err != nil {
		t.Fatalf("AcceptObfuscatedHeader() error = %v", err)
	}
	if state.SecretIndex != 1 {
		t.Fatalf("SecretIndex = %d, want 1", state.SecretIndex)
	}
	if state.Mode != FrameModePaddedIntermediate {
		t.Fatalf("Mode = %v, want padded intermediate", state.Mode)
	}
	if state.DCID != -3 {
		t.Fatalf("DCID = %d, want -3", state.DCID)
	}

	clientPlain := []byte("0123456789abcdef0123456789abcdef")
	clientCiphertext := append([]byte(nil), clientPlain...)
	clientEncrypt.XORKeyStream(clientCiphertext, clientCiphertext)
	state.Decrypt(clientCiphertext)
	if got := string(clientCiphertext); got != string(clientPlain) {
		t.Fatalf("client->server plaintext = %q, want %q", got, clientPlain)
	}

	serverPlain := []byte("server response bytes")
	serverCiphertext := append([]byte(nil), serverPlain...)
	state.Encrypt(serverCiphertext)
	clientDecrypt.XORKeyStream(serverCiphertext, serverCiphertext)
	if got := string(serverCiphertext); got != string(serverPlain) {
		t.Fatalf("server->client plaintext = %q, want %q", got, serverPlain)
	}
}

func TestObfuscatedHandshakeModesAndWrongSecret(t *testing.T) {
	secret := testSecret(0x70)
	modes := []FrameMode{FrameModeAbridged, FrameModeIntermediate, FrameModePaddedIntermediate}
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			wire, _, _ := buildClientHeader(t, secret, mode, 5)
			state, err := AcceptObfuscatedHeader(wire, [][16]byte{secret})
			if err != nil {
				t.Fatalf("AcceptObfuscatedHeader() error = %v", err)
			}
			if state.Mode != mode || state.DCID != 5 {
				t.Fatalf("state = mode %v dc %d, want mode %v dc 5", state.Mode, state.DCID, mode)
			}
		})
	}

	wire, _, _ := buildClientHeader(t, secret, FrameModeIntermediate, 2)
	if _, err := AcceptObfuscatedHeader(wire, [][16]byte{testSecret(0x71)}); err == nil {
		t.Fatal("AcceptObfuscatedHeader() accepted a wrong secret")
	}
	if _, err := AcceptObfuscatedHeader(wire, nil); err == nil {
		t.Fatal("AcceptObfuscatedHeader() accepted an empty secret set")
	}
}
