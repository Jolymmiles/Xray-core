// Package hellotest records the ClientHello a uTLS client sends and compares
// it with a golden file. It is for tests only.
package hellotest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const isolatedTestEnv = "XRAY_HELLOTEST_ISOLATED"

// Isolated runs the calling test again, alone, in a child process with the
// given extra flags, and reports whether it runs in that child. A test that
// sets process-wide state, as testing/cryptotest.SetGlobalRandom does for
// crypto/rand, must not share its process with other tests' goroutines.
func Isolated(t *testing.T, flags ...string) bool {
	t.Helper()
	if os.Getenv(isolatedTestEnv) == t.Name() {
		return true
	}
	arguments := append([]string{"-test.run=^" + t.Name() + "$", "-test.count=1", "-test.timeout=300s", "-test.v"}, flags...)
	child := exec.Command(os.Args[0], arguments...)
	child.Env = append(os.Environ(), isolatedTestEnv+"="+t.Name())
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated test failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "--- PASS: "+t.Name()+" ") {
		t.Fatalf("isolated child did not run %s:\n%s", t.Name(), output)
	}
	return false
}

// Capture is a connection that records what the client writes and answers
// every read with EOF, so a handshake sends its first ClientHello and stops.
type Capture struct {
	mu      sync.Mutex
	written []byte
}

func (c *Capture) Read([]byte) (int, error) { return 0, io.EOF }

func (c *Capture) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, b...)
	return len(b), nil
}

func (c *Capture) Close() error        { return nil }
func (c *Capture) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (c *Capture) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2} }
func (c *Capture) SetDeadline(time.Time) error      { return nil }
func (c *Capture) SetReadDeadline(time.Time) error  { return nil }
func (c *Capture) SetWriteDeadline(time.Time) error { return nil }

// FirstRecord returns the first TLS record written: the ClientHello.
func (c *Capture) FirstRecord() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.written) < 5 {
		return nil, errors.New("no TLS record was written")
	}
	end := 5 + int(c.written[3])<<8 + int(c.written[4])
	if c.written[0] != 22 || len(c.written) < end {
		return nil, fmt.Errorf("first write is not a complete handshake record: % x", c.written[:5])
	}
	return append([]byte(nil), c.written[:end]...), nil
}

// Snapshot is what a golden file keeps of one emitted ClientHello: the hash
// pins every byte, the rest shows what changed when it does not match.
type Snapshot struct {
	SHA256     string   `json:"sha256,omitempty"`
	Length     int      `json:"length,omitempty"`
	Extensions []uint16 `json:"extensions,omitempty"`
	Groups     []uint16 `json:"groups,omitempty"`
	KeyShares  []string `json:"keyShares,omitempty"`
	Versions   []uint16 `json:"versions,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// SessionIDOffset is where the legacy session ID starts in a ClientHello
// record: record header, handshake header, version, random, length byte.
const SessionIDOffset = 5 + 4 + 2 + 32 + 1

// Summarize parses a ClientHello record. It keeps extension order and the
// fields fingerprint changes are about.
func Summarize(record []byte) (Snapshot, error) {
	digest := sha256.Sum256(record)
	snapshot := Snapshot{SHA256: hex.EncodeToString(digest[:]), Length: len(record)}
	message := cryptobyte.String(record[5:])
	var handshakeType uint8
	var body, sessionID, ciphers, compression, extensions cryptobyte.String
	if !message.ReadUint8(&handshakeType) || handshakeType != 1 || !message.ReadUint24LengthPrefixed(&body) ||
		!body.Skip(2+32) || !body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&ciphers) || !body.ReadUint8LengthPrefixed(&compression) ||
		!body.ReadUint16LengthPrefixed(&extensions) {
		return snapshot, errors.New("malformed ClientHello")
	}
	for !extensions.Empty() {
		var extensionType uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extensionType) || !extensions.ReadUint16LengthPrefixed(&data) {
			return snapshot, errors.New("malformed extension")
		}
		snapshot.Extensions = append(snapshot.Extensions, extensionType)
		var err error
		switch extensionType {
		case 10: // supported_groups
			snapshot.Groups, err = readUint16s(&data, true)
		case 43: // supported_versions
			snapshot.Versions, err = readUint16s(&data, false)
		case 51: // key_share
			snapshot.KeyShares, err = readKeyShares(&data)
		case 16: // application_layer_protocol_negotiation
			snapshot.ALPN, err = readProtocols(&data)
		}
		if err != nil {
			return snapshot, err
		}
	}
	return snapshot, nil
}

func readUint16s(data *cryptobyte.String, wideLength bool) ([]uint16, error) {
	var list cryptobyte.String
	if wideLength && !data.ReadUint16LengthPrefixed(&list) || !wideLength && !data.ReadUint8LengthPrefixed(&list) {
		return nil, errors.New("malformed list")
	}
	var values []uint16
	for !list.Empty() {
		var value uint16
		if !list.ReadUint16(&value) {
			return nil, errors.New("malformed list entry")
		}
		values = append(values, value)
	}
	return values, nil
}

func readKeyShares(data *cryptobyte.String) ([]string, error) {
	var shares cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&shares) {
		return nil, errors.New("malformed key_share")
	}
	var values []string
	for !shares.Empty() {
		var group uint16
		var key cryptobyte.String
		if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&key) {
			return nil, errors.New("malformed key share")
		}
		values = append(values, fmt.Sprintf("%#04x/%d", group, len(key)))
	}
	return values, nil
}

func readProtocols(data *cryptobyte.String) ([]string, error) {
	var protocols cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&protocols) {
		return nil, errors.New("malformed ALPN")
	}
	var values []string
	for !protocols.Empty() {
		var protocol cryptobyte.String
		if !protocols.ReadUint8LengthPrefixed(&protocol) {
			return nil, errors.New("malformed ALPN protocol")
		}
		values = append(values, string(protocol))
	}
	return values, nil
}

// Compare checks got against the golden file, or rewrites the file when
// update is set.
func Compare(t *testing.T, file string, got map[string]Snapshot, update bool) {
	t.Helper()
	if update {
		encoded, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	encoded, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]Snapshot)
	if err := json.Unmarshal(encoded, &want); err != nil {
		t.Fatal(err)
	}
	for key, snapshot := range got {
		if expected, ok := want[key]; !ok {
			t.Errorf("%s: not in %s", key, file)
		} else if !reflect.DeepEqual(snapshot, expected) {
			t.Errorf("%s: ClientHello changed\n got: %+v\nwant: %+v", key, snapshot, expected)
		}
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("%s: in %s but no longer built", key, file)
		}
	}
}
