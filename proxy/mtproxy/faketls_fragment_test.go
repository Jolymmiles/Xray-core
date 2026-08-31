package mtproxy

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func fragmentClientHello(canonical []byte, fragmentSizes []int) []byte {
	payload := canonical[5:]
	result := make([]byte, 0, len(canonical)+5*len(fragmentSizes))
	offset := 0
	for _, requested := range fragmentSizes {
		if offset >= len(payload) {
			break
		}
		size := requested
		if size > len(payload)-offset {
			size = len(payload) - offset
		}
		result = append(result, 0x16, 0x03, 0x01, byte(size>>8), byte(size))
		result = append(result, payload[offset:offset+size]...)
		offset += size
	}
	if offset < len(payload) {
		size := len(payload) - offset
		result = append(result, 0x16, 0x03, 0x01, byte(size>>8), byte(size))
		result = append(result, payload[offset:]...)
	}
	return result
}

func TestReadFragmentedFakeTLSClientHello(t *testing.T) {
	secret := testSecret(0x66)
	canonical := buildTestClientHello(t, secret, "cover.example", time.Now().Unix())
	fragmented := fragmentClientHello(canonical, []int{3, 1, 7, 11, 23})
	var prefix [5]byte
	copy(prefix[:], fragmented[:5])
	result, err := readFakeTLSClientHello(bytes.NewReader(fragmented[5:]), prefix)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Canonical, canonical) {
		t.Fatalf("canonical ClientHello mismatch: got %x want %x", result.Canonical, canonical)
	}
	if !bytes.Equal(result.Wire, fragmented) {
		t.Fatal("wire capture does not preserve fragmented records")
	}

	registry, _ := NewSecretRegistry(1)
	registry.Add(secret)
	replay, _ := NewReplayCache(4, time.Minute)
	now := time.Now()
	auth := NewFakeTLSAuthenticator(registry, []string{"cover.example"}, replay, func() time.Time { return now })
	// The builder timestamp may differ by a second from now but remains inside the window.
	if _, err := auth.Authenticate(result.Canonical); err != nil {
		t.Fatalf("fragmented canonical authentication failed: %v", err)
	}
}

func TestCapturingReaderPreservesMalformedFragmentBytes(t *testing.T) {
	wire := []byte{0x16, 0x03, 0x01, 0, 3, 0x01, 0x00}
	var prefix [5]byte
	copy(prefix[:], wire[:5])
	capture := newCapturingReader(bytes.NewReader(wire[5:]), prefix[:])
	if _, err := readFakeTLSClientHello(capture, prefix); err == nil {
		t.Fatal("truncated fragmented ClientHello accepted")
	}
	if !bytes.Equal(capture.wire.Bytes(), wire) {
		t.Fatalf("captured wire = %x, want %x", capture.wire.Bytes(), wire)
	}
}

func TestReadFragmentedFakeTLSClientHelloRejectsExcessAndTrailingData(t *testing.T) {
	secret := testSecret(0x67)
	canonical := buildTestClientHello(t, secret, "cover.example", time.Now().Unix())
	oneByteFragments := make([]int, 20)
	for i := range oneByteFragments {
		oneByteFragments[i] = 1
	}
	fragmented := fragmentClientHello(canonical, oneByteFragments)
	var prefix [5]byte
	copy(prefix[:], fragmented[:5])
	if _, err := readFakeTLSClientHello(bytes.NewReader(fragmented[5:]), prefix); err == nil {
		t.Fatal("excessive TLS record fragmentation accepted")
	}

	trailing := append([]byte(nil), canonical...)
	binary.BigEndian.PutUint16(trailing[3:5], uint16(len(trailing)-4))
	trailing = append(trailing, 0)
	copy(prefix[:], trailing[:5])
	if _, err := readFakeTLSClientHello(bytes.NewReader(trailing[5:]), prefix); err == nil {
		t.Fatal("trailing handshake data accepted")
	}
}
