package tls

import (
	"encoding/binary"
	"strings"
	"testing"
)

var sniffTLSBenchmarkSink *SniffHeader
var sniffTLSDomainBenchmarkSink string

func invalidClientHelloRecord() []byte {
	record := make([]byte, 47)
	record[0], record[1], record[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(record[3:5], 42)
	return record
}

func benchmarkClientHello(serverName string) []byte {
	nameLength := len(serverName)
	serverNameListLength := 1 + 2 + nameLength
	serverNameExtensionLength := 2 + serverNameListLength
	extensionsLength := 4 + serverNameExtensionLength
	handshakeLength := 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensionsLength
	record := make([]byte, 5+handshakeLength)
	record[0], record[1], record[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(handshakeLength))
	handshake := record[5:]
	handshake[0] = 0x01
	handshake[1] = byte((handshakeLength - 4) >> 16)
	handshake[2] = byte((handshakeLength - 4) >> 8)
	handshake[3] = byte(handshakeLength - 4)
	handshake[4], handshake[5] = 0x03, 0x03
	offset := 4 + 2 + 32
	handshake[offset] = 0
	offset++
	binary.BigEndian.PutUint16(handshake[offset:offset+2], 2)
	offset += 2
	handshake[offset], handshake[offset+1] = 0x13, 0x01
	offset += 2
	handshake[offset], handshake[offset+1] = 1, 0
	offset += 2
	binary.BigEndian.PutUint16(handshake[offset:offset+2], uint16(extensionsLength))
	offset += 2
	binary.BigEndian.PutUint16(handshake[offset:offset+2], 0)
	binary.BigEndian.PutUint16(handshake[offset+2:offset+4], uint16(serverNameExtensionLength))
	offset += 4
	binary.BigEndian.PutUint16(handshake[offset:offset+2], uint16(serverNameListLength))
	offset += 2
	handshake[offset] = 0
	binary.BigEndian.PutUint16(handshake[offset+1:offset+3], uint16(nameLength))
	copy(handshake[offset+3:], serverName)
	return record
}

func TestBenchmarkClientHello(t *testing.T) {
	header, err := SniffTLS(benchmarkClientHello("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if header.Domain() != "example.com" {
		t.Fatalf("domain = %q", header.Domain())
	}
}

func BenchmarkSniffTLSServerName(b *testing.B) {
	payload := benchmarkClientHello("example.com")
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		header, err := SniffTLS(payload)
		if err != nil {
			b.Fatal(err)
		}
		sniffTLSBenchmarkSink = header
	}
}

func BenchmarkSniffTLSInvalidClientHello(b *testing.B) {
	payload := invalidClientHelloRecord()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := SniffTLS(payload); err == nil {
			b.Fatal("SniffTLS unexpectedly accepted malformed ClientHello")
		}
	}
}

func TestSniffTLSInvalidClientHelloAllocationBudget(t *testing.T) {
	payload := invalidClientHelloRecord()
	allocations := testing.AllocsPerRun(1000, func() {
		if _, err := SniffTLS(payload); err == nil {
			t.Fatal("SniffTLS unexpectedly accepted malformed ClientHello")
		}
	})
	if allocations != 0 {
		t.Fatalf("invalid ClientHello allocations = %.0f, want 0", allocations)
	}
}

func BenchmarkSniffTLSUppercaseServerNameAndNormalize(b *testing.B) {
	payload := benchmarkClientHello("WEB.WHATSAPP.COM")
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		header, err := SniffTLS(payload)
		if err != nil {
			b.Fatal(err)
		}
		sniffTLSBenchmarkSink = header
		sniffTLSDomainBenchmarkSink = strings.ToLower(header.Domain())
	}
}
