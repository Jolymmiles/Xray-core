// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"errors"
	"testing"
)

func TestFrameHeaderWireEncoding(t *testing.T) {
	var encoded [frameHeaderSize]byte
	encodeFrameHeader(&encoded, frameData, 0x78563412, 0x1234)
	want := [frameHeaderSize]byte{1, 2, 0x34, 0x12, 0x12, 0x34, 0x56, 0x78}
	if encoded != want {
		t.Fatalf("encoded header = %x, want %x", encoded, want)
	}
	header, err := decodeFrameHeader(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if header.command != frameData || header.streamID != 0x78563412 || header.length != 0x1234 {
		t.Fatalf("decoded header = %+v", header)
	}
}

func TestFrameHeaderRejectsInvalidControlFrames(t *testing.T) {
	tests := map[string][frameHeaderSize]byte{
		"version":         {2, 0, 0, 0, 3, 0, 0, 0},
		"command":         {1, 4, 0, 0, 3, 0, 0, 0},
		"control payload": {1, 0, 1, 0, 3, 0, 0, 0},
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeFrameHeader(&encoded); !errors.Is(err, ErrInvalidProtocol) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidProtocol)
			}
		})
	}
}
