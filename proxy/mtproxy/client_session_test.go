package mtproxy

import (
	"bytes"
	"testing"
)

func TestMiddleProxyRequestTransportFlags(t *testing.T) {
	encrypted := []byte{1, 0, 0, 0, 1, 0, 0, 0}
	unencrypted := make([]byte, 20)
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
			if got := middleProxyRequestFlags(test.mode, test.quick, test.payload); got != test.want {
				t.Fatalf("flags = %#x, want %#x", got, test.want)
			}
		})
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
