package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		mode benchmarkMode
	}{
		{name: "download", mode: modeDownload},
		{name: "upload", mode: modeUpload},
		{name: "bidirectional", mode: modeBidirectional},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := writeRequest(&encoded, benchmarkRequest{Mode: test.mode}); err != nil {
				t.Fatal(err)
			}
			request, err := readRequest(&encoded)
			if err != nil {
				t.Fatal(err)
			}
			if request.Mode != test.mode {
				t.Fatalf("mode = %v, want %v", request.Mode, test.mode)
			}
		})
	}
}

func TestReadRequestRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "short", payload: []byte("short")},
		{name: "bad magic", payload: append([]byte("BADMAGIC"), byte(modeDownload), 0, 0, 0)},
		{name: "bad mode", payload: append(append([]byte(nil), requestMagic...), 0xff, 0, 0, 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readRequest(bytes.NewReader(test.payload)); err == nil {
				t.Fatal("malformed request was accepted")
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	for input, want := range map[string]benchmarkMode{
		"download":      modeDownload,
		"upload":        modeUpload,
		"bidirectional": modeBidirectional,
		"bidi":          modeBidirectional,
	} {
		got, err := parseMode(input)
		if err != nil {
			t.Fatalf("parseMode(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("parseMode(%q) = %v, want %v", input, got, want)
		}
	}
	if _, err := parseMode("invalid"); err == nil {
		t.Fatal("invalid mode was accepted")
	}
}

func TestProtocolErrorPaths(t *testing.T) {
	if got := benchmarkMode(0xff).String(); got != "unknown(255)" {
		t.Fatalf("unknown mode string = %q", got)
	}
	if err := writeRequest(io.Discard, benchmarkRequest{}); err == nil {
		t.Fatal("invalid request mode was accepted")
	}
	wantErr := errors.New("write failed")
	if err := writeFull(errorWriter{err: wantErr}, []byte("payload")); !errors.Is(err, wantErr) {
		t.Fatalf("writeFull error = %v, want %v", err, wantErr)
	}
	if err := writeFull(zeroWriter{}, []byte("payload")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero write error = %v, want %v", err, io.ErrShortWrite)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
