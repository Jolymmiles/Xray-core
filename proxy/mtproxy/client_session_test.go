package mtproxy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMiddleProxyRequestTransportFlags(t *testing.T) {
	encrypted := []byte{1, 0, 0, 0, 1, 0, 0, 0}
	unencrypted := make([]byte, 24)
	binary.LittleEndian.PutUint32(unencrypted[16:20], 4)
	binary.LittleEndian.PutUint32(unencrypted[20:24], 0x60469778)
	tests := []struct {
		name    string
		mode    FrameMode
		quick   bool
		payload []byte
		want    uint32
	}{
		{"abridged", FrameModeAbridged, false, encrypted, 0x40021000},
		{"intermediate quick", FrameModeIntermediate, true, encrypted, 0xa0021000},
		{"padded", FrameModePaddedIntermediate, false, encrypted, 0x28021000},
		{"unauthenticated", FrameModeIntermediate, false, unencrypted, 0x20021002},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := middleProxyRequestFlags(test.mode, test.quick, test.payload)
			if err != nil || got != test.want {
				t.Fatalf("flags = %#x, %v, want %#x", got, err, test.want)
			}
		})
	}
}

func TestMiddleProxyRequestRejectsMalformedPlaintextMTProto(t *testing.T) {
	payload := make([]byte, 24)
	binary.LittleEndian.PutUint32(payload[16:20], 4)
	binary.LittleEndian.PutUint32(payload[20:24], 0xdeadbeef)
	if _, err := middleProxyRequestFlags(FrameModeIntermediate, false, payload); err == nil {
		t.Fatal("unsupported unauthenticated operation accepted")
	}
	if _, err := middleProxyRequestFlags(FrameModeIntermediate, false, make([]byte, 8)); err == nil {
		t.Fatal("truncated unauthenticated packet accepted")
	}
}

func TestLooksLikeFakeTLSDoesNotConsumeRandomObfuscatedPrefix(t *testing.T) {
	if looksLikeFakeTLS([5]byte{0x16, 0x7f, 0x22, 0, 64}) {
		t.Fatal("random obfuscated prefix classified as Fake TLS")
	}
	if !looksLikeFakeTLS([5]byte{0x16, 0x03, 0x01, 0, 128}) {
		t.Fatal("valid TLS ClientHello prefix not recognized")
	}
}

func TestClientQuickAckWireEncoding(t *testing.T) {
	confirm := uint32(0x11223344)
	if got := encodeClientQuickAck(FrameModeIntermediate, confirm); !bytes.Equal(got, []byte{0x44, 0x33, 0x22, 0x11}) {
		t.Fatalf("intermediate ack = %x", got)
	}
	if got := encodeClientQuickAck(FrameModePaddedIntermediate, confirm); !bytes.Equal(got, []byte{0x44, 0x33, 0x22, 0x11}) {
		t.Fatalf("padded ack = %x", got)
	}
	if got := encodeClientQuickAck(FrameModeAbridged, confirm); !bytes.Equal(got, []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Fatalf("abridged ack = %x", got)
	}
}
