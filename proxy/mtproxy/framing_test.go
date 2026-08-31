package mtproxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type fragmentReader struct {
	data []byte
	step int
}

func (r *fragmentReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.step
	if n <= 0 || n > len(p) {
		n = len(p)
	}
	if n > len(r.data) {
		n = len(r.data)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func encodedFrame(t *testing.T, mode FrameMode, payload []byte, padding int, quick bool) []byte {
	t.Helper()
	header, n, err := EncodeFrameHeader(mode, len(payload), padding, quick)
	if err != nil {
		t.Fatalf("EncodeFrameHeader() error = %v", err)
	}
	result := append([]byte(nil), header[:n]...)
	result = append(result, payload...)
	for i := 0; i < padding; i++ {
		result = append(result, byte(0xa0+i))
	}
	return result
}

func readTestFrame(t *testing.T, r io.Reader, mode FrameMode) ([]byte, FrameHeader) {
	t.Helper()
	header, err := ReadFrameHeader(r, mode, 1<<20)
	if err != nil {
		t.Fatalf("ReadFrameHeader() error = %v", err)
	}
	body := make([]byte, header.WireLength)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body[:header.PayloadLength], header
}

func TestFrameRoundTripFragmentedAndCoalesced(t *testing.T) {
	payload1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	payload2 := []byte{9, 10, 11, 12}
	modes := []FrameMode{FrameModeAbridged, FrameModeIntermediate, FrameModePaddedIntermediate}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			padding := 0
			if mode == FrameModePaddedIntermediate {
				padding = 3
			}
			stream := append(encodedFrame(t, mode, payload1, padding, true), encodedFrame(t, mode, payload2, padding, false)...)
			reader := &fragmentReader{data: stream, step: 1}

			first, firstHeader := readTestFrame(t, reader, mode)
			second, secondHeader := readTestFrame(t, reader, mode)
			if !bytes.Equal(first, payload1) || !bytes.Equal(second, payload2) {
				t.Fatalf("payloads = %v / %v, want %v / %v", first, second, payload1, payload2)
			}
			if !firstHeader.QuickAck || secondHeader.QuickAck {
				t.Fatalf("quick ack flags = %v / %v, want true / false", firstHeader.QuickAck, secondHeader.QuickAck)
			}
			if firstHeader.PaddingLength != padding || secondHeader.PaddingLength != padding {
				t.Fatalf("padding = %d / %d, want %d", firstHeader.PaddingLength, secondHeader.PaddingLength, padding)
			}
		})
	}
}

func TestAbridgedExtendedLength(t *testing.T) {
	payload := make([]byte, 0x7f*4)
	frame := encodedFrame(t, FrameModeAbridged, payload, 0, true)
	if frame[0] != 0xff {
		t.Fatalf("first byte = %#x, want 0xff", frame[0])
	}
	got, header := readTestFrame(t, bytes.NewReader(frame), FrameModeAbridged)
	if len(got) != len(payload) || !header.QuickAck || header.HeaderLength != 4 {
		t.Fatalf("decoded length=%d quick=%v header=%d", len(got), header.QuickAck, header.HeaderLength)
	}
}

func TestFrameRejectsMalformedLengths(t *testing.T) {
	tests := []struct {
		name string
		mode FrameMode
		data []byte
		max  int
	}{
		{name: "abridged empty", mode: FrameModeAbridged, data: []byte{0}, max: 1024},
		{name: "abridged overlong", mode: FrameModeAbridged, data: []byte{0x7f, 1, 0, 0}, max: 1024},
		{name: "intermediate unaligned", mode: FrameModeIntermediate, data: []byte{5, 0, 0, 0}, max: 1024},
		{name: "padded empty payload", mode: FrameModePaddedIntermediate, data: []byte{3, 0, 0, 0}, max: 1024},
		{name: "over max", mode: FrameModeIntermediate, data: func() []byte { var b [4]byte; binary.LittleEndian.PutUint32(b[:], 1028); return b[:] }(), max: 1024},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ReadFrameHeader(bytes.NewReader(test.data), test.mode, test.max); err == nil {
				t.Fatal("ReadFrameHeader() accepted malformed length")
			}
		})
	}
}

func TestEncodeFrameRejectsInvalidArguments(t *testing.T) {
	tests := []struct {
		mode    FrameMode
		payload int
		padding int
	}{
		{FrameModeAbridged, 3, 0},
		{FrameModeIntermediate, 4, 1},
		{FrameModePaddedIntermediate, 4, 4},
		{FrameMode(0), 4, 0},
	}
	for _, test := range tests {
		if _, _, err := EncodeFrameHeader(test.mode, test.payload, test.padding, false); err == nil {
			t.Fatalf("EncodeFrameHeader(%v, %d, %d) succeeded", test.mode, test.payload, test.padding)
		}
	}
}
