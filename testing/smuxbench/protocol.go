package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

type benchmarkMode byte

const (
	modeDownload benchmarkMode = 1 + iota
	modeUpload
	modeBidirectional
)

var requestMagic = []byte("SMUXBEN1")

const requestSize = 12

type benchmarkRequest struct {
	Mode benchmarkMode
}

func (m benchmarkMode) String() string {
	switch m {
	case modeDownload:
		return "download"
	case modeUpload:
		return "upload"
	case modeBidirectional:
		return "bidirectional"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

func (m benchmarkMode) valid() bool {
	return m == modeDownload || m == modeUpload || m == modeBidirectional
}

func parseMode(value string) (benchmarkMode, error) {
	switch strings.ToLower(value) {
	case "download":
		return modeDownload, nil
	case "upload":
		return modeUpload, nil
	case "bidirectional", "bidi":
		return modeBidirectional, nil
	default:
		return 0, fmt.Errorf("unknown benchmark mode %q", value)
	}
}

func writeRequest(writer io.Writer, request benchmarkRequest) error {
	if !request.Mode.valid() {
		return fmt.Errorf("invalid benchmark mode %d", request.Mode)
	}
	var encoded [requestSize]byte
	copy(encoded[:], requestMagic)
	encoded[len(requestMagic)] = byte(request.Mode)
	return writeFull(writer, encoded[:])
}

func readRequest(reader io.Reader) (benchmarkRequest, error) {
	var encoded [requestSize]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return benchmarkRequest{}, fmt.Errorf("read benchmark request: %w", err)
	}
	if string(encoded[:len(requestMagic)]) != string(requestMagic) {
		return benchmarkRequest{}, errors.New("invalid benchmark request magic")
	}
	request := benchmarkRequest{Mode: benchmarkMode(encoded[len(requestMagic)])}
	if !request.Mode.valid() {
		return benchmarkRequest{}, fmt.Errorf("invalid benchmark mode %d", request.Mode)
	}
	return request, nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written > 0 {
			payload = payload[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
