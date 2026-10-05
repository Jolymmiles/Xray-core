package quic_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
)

// quicTLSClientHello returns the ClientHello a crypto/tls QUIC client sends
// for serverName, as carried by the CRYPTO frames of its Initial packets. An
// empty serverName leaves out the server_name extension.
func quicTLSClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	conn := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: serverName == "", // #nosec G402 -- only the ClientHello is used
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
	}})
	conn.SetTransportParameters(nil)
	if err := conn.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for {
		event := conn.NextEvent()
		switch {
		case event.Kind == tls.QUICNoEvent:
			t.Fatal("the QUIC client sent no ClientHello")
		case event.Kind == tls.QUICWriteData && event.Level == tls.QUICEncryptionLevelInitial:
			return bytes.Clone(event.Data)
		}
	}
}

// cryptoFrame carries data at offset of the client's CRYPTO stream.
type cryptoFrame struct {
	offset int
	data   []byte
}

// hkdfExpandLabel is HKDF-Expand-Label from RFC 8446, Section 7.1, with an
// empty context.
func hkdfExpandLabel(t *testing.T, secret []byte, label string, length int) []byte {
	t.Helper()
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len("tls13 ")+len(label)))
	info = append(info, "tls13 "+label...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sealInitial builds a protected QUIC v1 client Initial packet for destConnID
// with packet number pn carrying frames (RFC 9000, Section 17.2.2; RFC 9001,
// Sections 5.2 to 5.4). It does not share code with the sniffer.
func sealInitial(t *testing.T, destConnID []byte, pn uint32, frames ...cryptoFrame) []byte {
	t.Helper()
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initialSecret, err := hkdf.Extract(sha256.New, destConnID, salt)
	if err != nil {
		t.Fatal(err)
	}
	clientSecret := hkdfExpandLabel(t, initialSecret, "client in", sha256.Size)
	block, err := aes.NewCipher(hkdfExpandLabel(t, clientSecret, "quic key", 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := hkdfExpandLabel(t, clientSecret, "quic iv", aead.NonceSize())
	headerProtection, err := aes.NewCipher(hkdfExpandLabel(t, clientSecret, "quic hp", 16))
	if err != nil {
		t.Fatal(err)
	}

	var payload []byte
	for _, frame := range frames {
		payload = append(payload, 0x06)
		payload = quicvarint.Append(payload, uint64(frame.offset))
		payload = quicvarint.Append(payload, uint64(len(frame.data)))
		payload = append(payload, frame.data...)
	}
	payload = append(payload, make([]byte, 32)...) // PADDING frames, so a header protection sample exists

	const pnLength = 4
	header := []byte{0xc0 | (pnLength - 1), 0, 0, 0, 1, byte(len(destConnID))}
	header = append(header, destConnID...)
	header = append(header, 0, 0) // no Source Connection ID, no token
	header = quicvarint.AppendWithLen(header, uint64(pnLength+len(payload)+aead.Overhead()), 2)
	pnOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, pn)

	nonce := bytes.Clone(iv)
	for i := range pnLength {
		nonce[len(nonce)-pnLength+i] ^= header[pnOffset+i]
	}
	packet := aead.Seal(header, nonce, payload, header)

	mask := make([]byte, headerProtection.BlockSize())
	headerProtection.Encrypt(mask, packet[pnOffset+4:pnOffset+4+len(mask)])
	packet[0] ^= mask[0] & 0x0f
	for i := range pnLength {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet
}

var reassemblyDestConnID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

// A ClientHello missing two bytes is incomplete wherever the gap is: the
// sniffer must ask for more data, neither reporting a server name read from
// bytes that never arrived nor rejecting the flow. Chrome sends CRYPTO frames
// as small as two bytes, so such gaps happen between its Initial packets.
func TestSniffQUICNeverReadsMissingClientHelloBytes(t *testing.T) {
	hello := quicTLSClientHello(t, "missing.sniff.test")
	for gap := 0; gap+2 <= len(hello); gap++ {
		packet := sealInitial(t, reassemblyDestConnID, 0,
			cryptoFrame{0, hello[:gap]},
			cryptoFrame{gap + 2, hello[gap+2:]},
		)
		header, err := quic.SniffQUIC(packet)
		if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
			domain := ""
			if header != nil {
				domain = header.Domain()
			}
			t.Fatalf("with bytes %d-%d of %d missing: SniffQUIC() = (%q, %v), want more data", gap, gap+1, len(hello), domain, err)
		}
	}
}

// Once the missing fragment arrives in a later packet, the ClientHello is
// complete and its server name is reported.
func TestSniffQUICCompletesClientHelloFromLaterPacket(t *testing.T) {
	const serverName = "gap.sniff.test"
	hello := quicTLSClientHello(t, serverName)
	nameOffset := bytes.Index(hello, []byte(serverName))
	if nameOffset < 2 {
		t.Fatalf("no server name %q in the ClientHello", serverName)
	}
	gap := nameOffset - 2 // the host_name length

	first := sealInitial(t, reassemblyDestConnID, 0,
		cryptoFrame{0, hello[:gap]},
		cryptoFrame{gap + 2, hello[gap+2:]},
	)
	second := sealInitial(t, reassemblyDestConnID, 1, cryptoFrame{gap, hello[gap : gap+2]})
	header, err := quic.SniffQUIC(append(bytes.Clone(first), second...))
	if err != nil {
		t.Fatalf("SniffQUIC() error = %v, want %q", err, serverName)
	}
	if header.Domain() != serverName {
		t.Fatalf("SniffQUIC() domain = %q, want %q", header.Domain(), serverName)
	}
}

// The client's CRYPTO stream starts with its ClientHello. A stream that starts
// with another handshake message, or a complete ClientHello without a server
// name, cannot become sniffable, so the flow is rejected at once instead of
// holding it until the dispatcher's sniffing deadline.
func TestSniffQUICRejectsUnsniffableCryptoStream(t *testing.T) {
	hello := quicTLSClientHello(t, "")
	tests := []struct {
		name   string
		stream []byte
	}{
		{"handshake message other than ClientHello", []byte{2, 0, 0, 4, 3, 3, 0, 0}},
		{"ClientHello without server name", hello},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := quic.SniffQUIC(sealInitial(t, reassemblyDestConnID, 0, cryptoFrame{0, tt.stream}))
			if err == nil || errors.Is(err, protocol.ErrProtoNeedMoreData) {
				t.Fatalf("SniffQUIC() error = %v, want a rejection", err)
			}
		})
	}
}
