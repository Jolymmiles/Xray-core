// SPDX-License-Identifier: MPL-2.0

package mplsmux

import "testing"

func FuzzFrameHeaderDecoder(f *testing.F) {
	f.Add([]byte{1, 2, 3, 0, 3, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		var encoded [frameHeaderSize]byte
		copy(encoded[:], input)
		_, _ = decodeFrameHeader(&encoded)
	})
}
