package singmux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestBrutalRequestRoundTripFragmented(t *testing.T) {
	var encoded bytes.Buffer
	const want uint64 = 123456789
	if err := writeBrutalRequest(&encoded, want); err != nil {
		t.Fatal(err)
	}
	if got := encoded.Bytes(); !bytes.Equal(got, []byte{0, 0, 0, 0, 7, 91, 205, 21}) {
		t.Fatalf("request bytes = %x", got)
	}
	value, err := readBrutalRequest(&fragmentedReader{data: encoded.Bytes(), max: 1})
	if err != nil {
		t.Fatal(err)
	}
	if value != want {
		t.Fatalf("request value = %d, want %d", value, want)
	}
}

func TestBrutalCodecRejectsShortData(t *testing.T) {
	if _, err := readBrutalRequest(bytes.NewReader(make([]byte, 7))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short request error = %v", err)
	}
	if _, err := readBrutalResponse(bytes.NewReader([]byte{1})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short response error = %v", err)
	}
}

func TestBrutalResponseRoundTripAndDiagnosticLimit(t *testing.T) {
	var success bytes.Buffer
	if err := writeBrutalResponse(&success, 987654321, true, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := readBrutalResponse(&fragmentedReader{data: success.Bytes(), max: 2}); err != nil || got != 987654321 {
		t.Fatalf("success response = %d, %v", got, err)
	}

	message := bytes.Repeat([]byte("x"), maxDiagnosticBytes+1)
	var failure bytes.Buffer
	if err := writeBrutalResponse(&failure, 0, false, string(message)); err != nil {
		t.Fatal(err)
	}
	var encodedLength []byte
	encodedLength = binary.AppendUvarint(encodedLength, maxDiagnosticBytes)
	if failure.Len() != 1+len(encodedLength)+maxDiagnosticBytes {
		t.Fatalf("encoded diagnostic length = %d, want %d", failure.Len(), 1+len(encodedLength)+maxDiagnosticBytes)
	}
	if _, err := readBrutalResponse(bytes.NewReader(append([]byte{0}, append([]byte{0x80, 0x80, 0x04}, make([]byte, 0)...)...))); err == nil {
		t.Fatal("oversized diagnostic must be rejected")
	}
}

func TestBrutalSuccessResponseGolden(t *testing.T) {
	var encoded bytes.Buffer
	if err := writeBrutalResponse(&encoded, 0x0102030405060708, true, ""); err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 1, 2, 3, 4, 5, 6, 7, 8}
	if !bytes.Equal(encoded.Bytes(), want) {
		t.Fatalf("response bytes = %x, want %x", encoded.Bytes(), want)
	}
}

func TestBrutalResponseRejectsInvalidUTF8(t *testing.T) {
	encoded := []byte{0, 1, 0xff}
	if _, err := readBrutalResponse(bytes.NewReader(encoded)); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid diagnostic error = %v", err)
	}
}

func TestBrutalResponseWriterSanitizesAndTruncatesRunes(t *testing.T) {
	var sanitized bytes.Buffer
	if err := writeBrutalResponse(&sanitized, 0, false, string([]byte{0xff})); err != nil {
		t.Fatal(err)
	}
	if _, err := readBrutalResponse(bytes.NewReader(sanitized.Bytes())); err == nil {
		t.Fatal("sanitized diagnostic should be encoded as a valid error response")
	}
	length, err := readUvarint(bytes.NewReader(sanitized.Bytes()[1:]))
	if err != nil {
		t.Fatal(err)
	}
	if length != uint64(len([]byte("�"))) {
		t.Fatalf("sanitized length = %d", length)
	}

	message := strings.Repeat("a", maxDiagnosticBytes-2) + "€"
	var truncated bytes.Buffer
	if err := writeBrutalResponse(&truncated, 0, false, message); err != nil {
		t.Fatal(err)
	}
	encoded := truncated.Bytes()
	length, err = readUvarint(bytes.NewReader(encoded[1:]))
	if err != nil {
		t.Fatal(err)
	}
	if length > maxDiagnosticBytes {
		t.Fatalf("diagnostic length = %d, exceeds limit", length)
	}
	var offset int
	for offset < len(encoded[1:]) && encoded[1+offset]&0x80 != 0 {
		offset++
	}
	offset++
	payload := encoded[1+offset:]
	if len(payload) != maxDiagnosticBytes-2 || !utf8.Valid(payload) {
		t.Fatalf("truncated payload length/UTF-8 = %d/%v", len(payload), utf8.Valid(payload))
	}
}

func TestUnwrapBrutalConnThroughKnownWrappers(t *testing.T) {
	base := &brutalSyscallConn{}
	wrapped := &brutalRawWrapper{Conn: &brutalNetWrapper{Conn: &stat.CounterConnection{Connection: base}}}
	got, err := unwrapBrutalConn(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Fatalf("unwrapped conn = %T, want base", got)
	}
}

func TestUnwrapBrutalConnStopsAtBound(t *testing.T) {
	conn := net.Conn(&brutalNetWrapper{})
	for i := 0; i < maxBrutalUnwrapDepth+1; i++ {
		conn = &brutalNetWrapper{Conn: conn}
	}
	if _, err := unwrapBrutalConn(conn); err == nil {
		t.Fatal("unwrap must stop at the bounded depth")
	}
}

type fragmentedReader struct {
	data []byte
	max  int
}

func (r *fragmentedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) > r.max {
		p = p[:r.max]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type brutalNetWrapper struct{ net.Conn }

func (c *brutalNetWrapper) NetConn() net.Conn { return c.Conn }

type brutalRawWrapper struct{ net.Conn }

func (c *brutalRawWrapper) RawConn() net.Conn { return c.Conn }

type brutalSyscallConn struct{}

func (c *brutalSyscallConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *brutalSyscallConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *brutalSyscallConn) Close() error                     { return nil }
func (c *brutalSyscallConn) LocalAddr() net.Addr              { return nil }
func (c *brutalSyscallConn) RemoteAddr() net.Addr             { return nil }
func (c *brutalSyscallConn) SetDeadline(time.Time) error      { return nil }
func (c *brutalSyscallConn) SetReadDeadline(time.Time) error  { return nil }
func (c *brutalSyscallConn) SetWriteDeadline(time.Time) error { return nil }
func (c *brutalSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("not used")
}
