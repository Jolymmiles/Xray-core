package tls_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	. "github.com/xtls/xray-core/common/protocol/tls"
)

// tlsCorpusSeeds returns the captured first records of the corpus.
func tlsCorpusSeeds(f *testing.F) [][]byte {
	f.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "*.bin"))
	if err != nil || len(paths) == 0 {
		f.Fatalf("no TLS corpus: %v", err)
	}
	var seeds [][]byte
	for _, path := range paths {
		record, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, record)
	}
	return seeds
}

// nameFromInput reports whether name, as ReadClientHello reports it, comes
// from data: it is the bytes of data, or their lower-case form. A host_name
// of zero bytes, which RFC 6066 does not allow, comes out as an empty name,
// which the dispatcher does not route by. A name with bytes outside ASCII,
// which RFC 6066 does not allow either, is lower-cased as UTF-8, invalid
// sequences becoming U+FFFD, so only ASCII names are checked against data.
func nameFromInput(name string, data []byte) bool {
	for i := range len(name) {
		if name[i] >= 0x80 {
			return true
		}
	}
	return name == "" || bytes.Contains(data, []byte(name)) || bytes.Contains(bytes.ToLower(data), []byte(name))
}

// ReadClientHello parses a handshake message a client chose, from TLS records
// or QUIC CRYPTO frames. Whatever it holds, it must not panic, and a server
// name it reports must come from the message.
func FuzzReadClientHello(f *testing.F) {
	for _, record := range tlsCorpusSeeds(f) {
		f.Add(record[5:])
	}
	f.Fuzz(func(t *testing.T, hello []byte) {
		var header SniffHeader
		if err := ReadClientHello(hello, &header); err == nil && !nameFromInput(header.Domain(), hello) {
			t.Fatalf("server name %q is not in the ClientHello", header.Domain())
		}
	})
}

// recordPayloads returns the handshake bytes TLS records carry, without
// their 5-byte headers, as SniffTLS reassembles a ClientHello across records.
func recordPayloads(records []byte) []byte {
	var payload []byte
	for len(records) >= 5 {
		n := min(int(records[3])<<8|int(records[4]), len(records)-5)
		payload = append(payload, records[5:5+n]...)
		records = records[5+n:]
	}
	return payload
}

// SniffTLS reads TLS records the dispatcher borrows and forwards afterwards.
// Whatever they hold, it must not panic or modify them, and a server name it
// reports must come from the handshake bytes they carry.
func FuzzSniffTLS(f *testing.F) {
	for _, record := range tlsCorpusSeeds(f) {
		f.Add(record)
		f.Add(record[:len(record)/2])
	}
	f.Fuzz(func(t *testing.T, records []byte) {
		sent := bytes.Clone(records)
		header, err := SniffTLS(records)
		if !bytes.Equal(records, sent) {
			t.Fatal("SniffTLS modified its input")
		}
		if err == nil && !nameFromInput(header.Domain(), recordPayloads(records)) {
			t.Fatalf("server name %q is not in the records", header.Domain())
		}
	})
}
