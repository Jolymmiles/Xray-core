package singmux

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	X "github.com/xtls/xray-core/common/net"
)

func TestCarrierRequestGolden(t *testing.T) {
	tests := []struct {
		name     string
		protocol byte
		padding  []byte
		wantHex  string
	}{
		{name: "smux plain", protocol: protocolSMUX, wantHex: "0000"},
		{name: "smux padded", protocol: protocolSMUX, padding: []byte{0xaa, 0xbb, 0xcc}, wantHex: "0100010003aabbcc"},
		{name: "h2mux plain", protocol: protocolH2MUX, wantHex: "0002"},
		{name: "h2mux padded", protocol: protocolH2MUX, padding: []byte{0xaa, 0xbb, 0xcc}, wantHex: "0102010003aabbcc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := writeCarrierRequest(&encoded, test.protocol, test.padding); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(encoded.Bytes()); got != test.wantHex {
				t.Fatalf("carrier request = %s, want %s", got, test.wantHex)
			}
			request, err := readCarrierRequest(bytes.NewReader(encoded.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if request.Protocol != test.protocol || !bytes.Equal(request.Padding, test.padding) {
				t.Fatalf("decoded request = %#v", request)
			}
		})
	}
}

func TestCarrierVersionOneWithoutPadding(t *testing.T) {
	for _, protocol := range []byte{protocolSMUX, protocolH2MUX} {
		request, err := readCarrierRequest(bytes.NewReader([]byte{carrierVersionPadded, protocol, 0}))
		if err != nil {
			t.Fatal(err)
		}
		if request.Version != carrierVersionPadded || request.Protocol != protocol || request.Padding != nil {
			t.Fatalf("request = %#v", request)
		}
	}
}

func TestStreamRequestGolden(t *testing.T) {
	tests := []struct {
		name        string
		flags       uint16
		destination X.Destination
		wantHex     string
	}{
		{
			name:        "tcp-domain",
			destination: X.TCPDestination(X.DomainAddress("example.com"), 443),
			wantHex:     "0000030b6578616d706c652e636f6d01bb",
		},
		{
			name:        "udp-ipv4-packet-address",
			flags:       streamFlagUDP | streamFlagPacketAddr,
			destination: X.UDPDestination(X.IPAddress([]byte{1, 2, 3, 4}), 53),
			wantHex:     "000301010203040035",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := writeStreamRequest(&encoded, test.flags, test.destination); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(encoded.Bytes()); got != test.wantHex {
				t.Fatalf("stream request = %s, want %s", got, test.wantHex)
			}
			flags, destination, err := readStreamRequest(bytes.NewReader(encoded.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if flags != test.flags || destination.String() != test.destination.String() || destination.Network != test.destination.Network {
				t.Fatalf("decoded request = flags %d, destination %s", flags, destination)
			}
		})
	}
}

func TestPacketGolden(t *testing.T) {
	destination := X.UDPDestination(X.IPAddress([]byte{1, 2, 3, 4}), 53)
	var encoded bytes.Buffer
	if err := writePacket(&encoded, destination, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	const wantHex = "010102030400350003616263"
	if got := hex.EncodeToString(encoded.Bytes()); got != wantHex {
		t.Fatalf("packet = %s, want %s", got, wantHex)
	}
	gotDestination, payload, err := readPacket(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if gotDestination.String() != destination.String() || string(payload) != "abc" {
		t.Fatalf("decoded packet = %s %q", gotDestination, payload)
	}
}

func TestStreamErrorResponseIsBounded(t *testing.T) {
	encoded := []byte{streamStatusError, 0x81, 0x80, 0x04}
	if err := readStreamResponse(bytes.NewReader(encoded)); err == nil {
		t.Fatal("oversized error response must be rejected")
	}
}

func TestStreamResponseRoundTrip(t *testing.T) {
	var success bytes.Buffer
	if err := writeStreamResponse(&success, nil); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(&success); err != nil {
		t.Fatal(err)
	}

	var failure bytes.Buffer
	if err := writeStreamResponse(&failure, errors.New("denied")); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(&failure); err == nil || err.Error() != "denied" {
		t.Fatalf("error response = %v, want denied", err)
	}
	if err := readStreamResponse(bytes.NewReader([]byte{9})); err == nil {
		t.Fatal("unknown response status must be rejected")
	}
}

func TestIPv6DestinationRoundTrip(t *testing.T) {
	want := X.TCPDestination(X.IPAddress([]byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}), 8443)
	var encoded bytes.Buffer
	if err := writeDestination(&encoded, want); err != nil {
		t.Fatal(err)
	}
	got, err := readDestination(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Address.String() != want.Address.String() || got.Port != want.Port {
		t.Fatalf("destination = %s:%d, want %s:%d", got.Address, got.Port, want.Address, want.Port)
	}
}

func TestProtocolRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{"carrier version", func() error { _, err := readCarrierRequest(bytes.NewReader([]byte{2, 0})); return err }},
		{"carrier protocol", func() error { _, err := readCarrierRequest(bytes.NewReader([]byte{0, 1})); return err }},
		{"padding flag", func() error { _, err := readCarrierRequest(bytes.NewReader([]byte{1, 0, 2})); return err }},
		{"truncated padding", func() error { _, err := readCarrierRequest(bytes.NewReader([]byte{1, 0, 1, 0, 2, 0})); return err }},
		{"stream flags", func() error { _, _, err := readStreamRequest(bytes.NewReader([]byte{0x80, 0})); return err }},
		{"packet flag on tcp", func() error { _, _, err := readStreamRequest(bytes.NewReader([]byte{0, 2})); return err }},
		{"address family", func() error { _, err := readDestination(bytes.NewReader([]byte{9})); return err }},
		{"empty domain", func() error { _, err := readDestination(bytes.NewReader([]byte{addressDomain, 0})); return err }},
		{"truncated ipv4", func() error { _, err := readDestination(bytes.NewReader([]byte{addressIPv4, 1})); return err }},
		{"truncated packet", func() error {
			_, _, err := readPacket(bytes.NewReader([]byte{addressIPv4, 1, 2, 3, 4, 0, 53, 0, 2, 1}))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("malformed input must be rejected")
			}
		})
	}
}

func TestProtocolRejectsInvalidOutput(t *testing.T) {
	for _, protocol := range []byte{1, 3, 255} {
		if err := writeCarrierRequest(io.Discard, protocol, nil); err == nil {
			t.Fatalf("carrier protocol %d must be rejected", protocol)
		}
	}
	if err := writeCarrierRequest(io.Discard, protocolSMUX, make([]byte, 65536)); err == nil {
		t.Fatal("oversized carrier padding must be rejected")
	}
	if err := writeStreamRequest(io.Discard, 0x8000, X.TCPDestination(X.LocalHostIP, 80)); err == nil {
		t.Fatal("unsupported stream flags must be rejected")
	}
	if err := writeDestination(io.Discard, X.Destination{}); err == nil {
		t.Fatal("missing address must be rejected")
	}
	if err := writeDestination(io.Discard, X.TCPDestination(X.DomainAddress(""), 80)); err == nil {
		t.Fatal("empty domain must be rejected")
	}
	if err := writePacket(io.Discard, X.UDPDestination(X.LocalHostIP, 53), make([]byte, 65536)); err == nil {
		t.Fatal("oversized UDP payload must be rejected")
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteFullRejectsNoProgress(t *testing.T) {
	if err := writeFull(zeroWriter{}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("write error = %v, want io.ErrShortWrite", err)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteFullPropagatesWriterError(t *testing.T) {
	if err := writeFull(errorWriter{}, []byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error = %v, want io.ErrClosedPipe", err)
	}
}
