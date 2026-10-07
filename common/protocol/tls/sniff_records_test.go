package tls_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/common/protocol/tls"
)

// readTLSCorpus returns a captured first record; see testdata/PROVENANCE.md.
func readTLSCorpus(t *testing.T, name string) []byte {
	t.Helper()
	record, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// fragmentRecords carries the handshake data of a single TLS record in
// records of at most n bytes, as RFC 8446, Section 5.1 allows.
func fragmentRecords(record []byte, n int) []byte {
	var records []byte
	for fragment := range slices.Chunk(record[5:], n) {
		records = append(records, 0x16, 0x03, 0x01, byte(len(fragment)>>8), byte(len(fragment)))
		records = append(records, fragment...)
	}
	return records
}

// ClientHellos captured from Chrome, Firefox and curl yield their server
// names.
func TestSniffTLSClientCorpus(t *testing.T) {
	tests := []struct {
		file, domain string
	}{
		{"tls-chrome153.bin", "chrome.sniff.test"},
		{"tls-firefox153esr.bin", "firefox.sniff.test"},
		{"tls-curl8.18-openssl3.5.bin", "curl.sniff.test"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			header, err := SniffTLS(readTLSCorpus(t, tt.file))
			if err != nil || header.Domain() != tt.domain {
				t.Fatalf("SniffTLS() = (%v, %v), want %q", header, err, tt.domain)
			}
		})
	}
}

// A ClientHello can be fragmented across handshake records. Hysteria 2.13.0
// reassembles it, and Xray's own fragment mask splits ClientHellos this way.
func TestSniffTLSClientHelloAcrossRecords(t *testing.T) {
	chrome := readTLSCorpus(t, "tls-chrome153.bin")
	for _, size := range []int{1, 3, 100, 333, 1500} {
		records := fragmentRecords(chrome, size)
		received := bytes.Clone(records)
		header, err := SniffTLS(records)
		if err != nil || header.Domain() != "chrome.sniff.test" {
			t.Errorf("with %d-byte records: SniffTLS() = (%v, %v), want chrome.sniff.test", size, header, err)
		}
		if !bytes.Equal(records, received) {
			t.Errorf("with %d-byte records: SniffTLS modified its input", size)
		}
	}
}

// Until the last fragment arrives, the sniffer asks for more data; it neither
// reports a name nor rejects the connection.
func TestSniffTLSWaitsForRemainingRecords(t *testing.T) {
	records := fragmentRecords(readTLSCorpus(t, "tls-chrome153.bin"), 100)
	for _, cut := range []int{105, 210, 300, len(records) - 1} {
		header, err := SniffTLS(records[:cut])
		if !errors.Is(err, protocol.ErrProtoNeedMoreData) && !errors.Is(err, common.ErrNoClue) {
			t.Errorf("with %d of %d bytes: SniffTLS() = (%v, %v), want more data", cut, len(records), header, err)
		}
	}
}

// A ClientHello ends with the record that completes it: a record of another
// type may follow it, but one that interrupts it rejects the stream.
func TestSniffTLSClientHelloEndsAtItsLastRecord(t *testing.T) {
	chrome := readTLSCorpus(t, "tls-chrome153.bin")
	changeCipherSpec := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

	header, err := SniffTLS(append(bytes.Clone(chrome), changeCipherSpec...))
	if err != nil || header.Domain() != "chrome.sniff.test" {
		t.Errorf("ClientHello followed by another record: SniffTLS() = (%v, %v), want chrome.sniff.test", header, err)
	}

	interrupted := append(fragmentRecords(chrome, 100)[:105], changeCipherSpec...)
	header, err = SniffTLS(interrupted)
	if err == nil || errors.Is(err, protocol.ErrProtoNeedMoreData) || errors.Is(err, common.ErrNoClue) {
		t.Errorf("ClientHello interrupted by another record: SniffTLS() = (%v, %v), want a rejection", header, err)
	}
}
