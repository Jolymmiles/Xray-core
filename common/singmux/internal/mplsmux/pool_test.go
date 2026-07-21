// SPDX-License-Identifier: MPL-2.0

package mplsmux

import "testing"

func TestReceivePoolClasses(t *testing.T) {
	tests := []struct {
		size  int
		class int
		cap   int
	}{
		{size: 0, class: 0, cap: 1024},
		{size: 1024, class: 0, cap: 1024},
		{size: 1025, class: 1, cap: 2048},
		{size: 32768, class: 5, cap: 32768},
		{size: 65536, class: 6, cap: 65536},
		{size: 65537, class: -1, cap: 65537},
	}
	for _, test := range tests {
		if class := receivePoolClass(test.size); class != test.class {
			t.Fatalf("receivePoolClass(%d) = %d, want %d", test.size, class, test.class)
		}
		buffer := acquireReceiveBuffer(test.size)
		if len(buffer) != test.size || cap(buffer) != test.cap {
			t.Fatalf("buffer(%d) has len/cap %d/%d, want %d/%d", test.size, len(buffer), cap(buffer), test.size, test.cap)
		}
		releaseReceiveBuffer(buffer)
	}
}

func TestFramePoolIncludesMaximumWireFrame(t *testing.T) {
	buffer := acquireFrameBuffer(frameHeaderSize + maxFramePayload)
	if len(buffer) != frameHeaderSize+maxFramePayload || cap(buffer) != 128*1024 {
		t.Fatalf("maximum frame has len/cap %d/%d", len(buffer), cap(buffer))
	}
	releaseFrameBuffer(buffer)
}

func TestPoolsIgnoreUnpooledSizes(t *testing.T) {
	releaseReceiveBuffer(make([]byte, 17))
	releaseFrameBuffer(make([]byte, 17))
	buffer := acquireFrameBuffer(256*1024 + 1)
	if len(buffer) != 256*1024+1 || cap(buffer) != 256*1024+1 {
		t.Fatalf("oversized frame has len/cap %d/%d", len(buffer), cap(buffer))
	}
}
