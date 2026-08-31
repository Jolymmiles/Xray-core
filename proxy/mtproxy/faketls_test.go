package mtproxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func buildTestClientHello(t *testing.T, secret [16]byte, domain string, timestamp int64) []byte {
	t.Helper()
	sessionID := bytes.Repeat([]byte{0x42}, 32)
	body := make([]byte, 0, 256)
	body = append(body, 0x03, 0x03)
	randomOffsetBody := len(body)
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = append(body, 0, 4, 0x13, 0x01, 0x13, 0x02)
	body = append(body, 1, 0)

	serverName := []byte(domain)
	sni := make([]byte, 0, len(serverName)+5)
	sni = append(sni, byte((len(serverName)+3)>>8), byte(len(serverName)+3), 0)
	sni = append(sni, byte(len(serverName)>>8), byte(len(serverName)))
	sni = append(sni, serverName...)
	extensions := []byte{0, 0, byte(len(sni) >> 8), byte(len(sni))}
	extensions = append(extensions, sni...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	hello := []byte{0x16, 0x03, 0x01, 0, 0, 0x01, 0, 0, 0}
	hello = append(hello, body...)
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(hello)-5))
	handshakeLength := len(hello) - 9
	hello[6], hello[7], hello[8] = byte(handshakeLength>>16), byte(handshakeLength>>8), byte(handshakeLength)

	randomOffset := 9 + randomOffsetBody
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write(hello)
	expected := mac.Sum(nil)
	copy(hello[randomOffset:randomOffset+28], expected[:28])
	encodedTimestamp := uint32(timestamp) ^ binary.LittleEndian.Uint32(expected[28:32])
	binary.LittleEndian.PutUint32(hello[randomOffset+28:randomOffset+32], encodedTimestamp)
	return hello
}

func TestFakeTLSAuthenticateClientHelloAndReplay(t *testing.T) {
	registry, _ := NewSecretRegistry(4)
	secret := testSecret(90)
	fingerprint, _, _ := registry.Add(secret)
	replay, _ := NewReplayCache(16, 48*time.Hour)
	now := time.Unix(1_700_000_000, 0)
	auth := NewFakeTLSAuthenticator(registry, []string{"cover.example"}, replay, func() time.Time { return now })
	hello := buildTestClientHello(t, secret, "cover.example", now.Unix())

	result, err := auth.Authenticate(hello)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.Fingerprint != fingerprint || result.ServerName != "cover.example" || result.CipherSuite != 0x1301 {
		t.Fatalf("Authenticate() = %+v", result)
	}
	if _, err := auth.Authenticate(hello); !errors.Is(err, ErrFakeTLSReplay) {
		t.Fatalf("replay error = %v, want ErrFakeTLSReplay", err)
	}
}

func TestFakeTLSRejectsWrongDomainSecretAndTimestamp(t *testing.T) {
	registry, _ := NewSecretRegistry(2)
	secret := testSecret(100)
	registry.Add(secret)
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name    string
		hello   []byte
		domains []string
	}{
		{"wrong domain", buildTestClientHello(t, secret, "other.example", now.Unix()), []string{"cover.example"}},
		{"wrong secret", buildTestClientHello(t, testSecret(101), "cover.example", now.Unix()), []string{"cover.example"}},
		{"old timestamp", buildTestClientHello(t, secret, "cover.example", now.Add(-11*time.Minute).Unix()), []string{"cover.example"}},
		{"future timestamp", buildTestClientHello(t, secret, "cover.example", now.Add(4*time.Second).Unix()), []string{"cover.example"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			replay, _ := NewReplayCache(16, 48*time.Hour)
			auth := NewFakeTLSAuthenticator(registry, test.domains, replay, func() time.Time { return now })
			if _, err := auth.Authenticate(test.hello); err == nil {
				t.Fatal("Authenticate() accepted invalid ClientHello")
			}
		})
	}
}

func TestFakeTLSFallbackIsRestrictedToAllowedSNI(t *testing.T) {
	secret := testSecret(110)
	hello := buildTestClientHello(t, secret, "cover.example", time.Now().Unix())
	domain, ok := FakeTLSFallbackServerName(hello, []string{"cover.example"})
	if !ok || domain != "cover.example" {
		t.Fatalf("fallback = %q, %v", domain, ok)
	}
	if _, ok := FakeTLSFallbackServerName(hello, []string{"other.example"}); ok {
		t.Fatal("fallback allowed an unconfigured SNI")
	}
}

func TestFakeTLSServerHelloHMAC(t *testing.T) {
	registry, _ := NewSecretRegistry(1)
	secret := testSecret(120)
	registry.Add(secret)
	now := time.Unix(1_700_000_000, 0)
	replay, _ := NewReplayCache(4, time.Hour)
	auth := NewFakeTLSAuthenticator(registry, []string{"cover.example"}, replay, func() time.Time { return now })
	result, err := auth.Authenticate(buildTestClientHello(t, secret, "cover.example", now.Unix()))
	if err != nil {
		t.Fatal(err)
	}

	response, err := BuildFakeTLSServerHello(result, bytes.NewReader(bytes.Repeat([]byte{0x55}, 4096)), 256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(response, []byte{0x16, 0x03, 0x03}) || !bytes.Contains(response, []byte{0x14, 0x03, 0x03, 0, 1, 1, 0x17, 0x03, 0x03}) {
		t.Fatalf("response is not TLS-shaped: %x", response[:min(len(response), 32)])
	}
	serverRandom := append([]byte(nil), response[11:43]...)
	zeroed := append([]byte(nil), response...)
	clear(zeroed[11:43])
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write(result.ClientRandom[:])
	_, _ = mac.Write(zeroed)
	if !hmac.Equal(serverRandom, mac.Sum(nil)) {
		t.Fatal("server random HMAC mismatch")
	}
}

func TestFakeTLSRequiresPaddedIntermediateInnerHeader(t *testing.T) {
	registry, _ := NewSecretRegistry(1)
	secret := testSecret(125)
	registry.Add(secret)
	now := time.Unix(1_700_000_000, 0)
	replay, _ := NewReplayCache(4, time.Hour)
	authenticator := NewFakeTLSAuthenticator(registry, []string{"cover.example"}, replay, func() time.Time { return now })
	auth, err := authenticator.Authenticate(buildTestClientHello(t, secret, "cover.example", now.Unix()))
	if err != nil {
		t.Fatal(err)
	}

	padded, _, _ := buildClientHeader(t, secret, FrameModePaddedIntermediate, 2)
	if _, err := auth.AcceptInnerHeader(padded); err != nil {
		t.Fatalf("AcceptInnerHeader(padded) error = %v", err)
	}
	intermediate, _, _ := buildClientHeader(t, secret, FrameModeIntermediate, 2)
	if _, err := auth.AcceptInnerHeader(intermediate); err == nil {
		t.Fatal("AcceptInnerHeader accepted non-padded transport")
	}
}

func TestConsumeFakeTLSChangeCipherSpec(t *testing.T) {
	valid := []byte{0x14, 0x03, 0x03, 0, 1, 1}
	if err := ConsumeFakeTLSChangeCipherSpec(&fragmentReader{data: valid, step: 1}); err != nil {
		t.Fatalf("valid ChangeCipherSpec error = %v", err)
	}
	invalid := append([]byte(nil), valid...)
	invalid[5] = 0
	if err := ConsumeFakeTLSChangeCipherSpec(bytes.NewReader(invalid)); err == nil {
		t.Fatal("invalid ChangeCipherSpec accepted")
	}
}

func TestTLSRecordReaderFragmentationAndWriter(t *testing.T) {
	plaintext := []byte(strings.Repeat("record-payload-", 40))
	var wire bytes.Buffer
	if err := WriteFakeTLSApplicationData(&wire, plaintext, 37); err != nil {
		t.Fatal(err)
	}
	reader := NewFakeTLSRecordReader(&fragmentReader{data: wire.Bytes(), step: 1}, 1024)
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("record plaintext length = %d, want %d", len(got), len(plaintext))
	}

	invalid := NewFakeTLSRecordReader(bytes.NewReader([]byte{0x16, 0x03, 0x03, 0, 1, 0}), 1024)
	if _, err := io.ReadAll(invalid); err == nil {
		t.Fatal("record reader accepted handshake record")
	}
}
