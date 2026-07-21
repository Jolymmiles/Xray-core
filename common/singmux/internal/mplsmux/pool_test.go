// SPDX-License-Identifier: MPL-2.0

package mplsmux

import "testing"

func TestReceiveBuffersUseOwnedXrayBuffers(t *testing.T) {
	for _, size := range []int{1024, 8 * 1024, 32 * 1024, 65535} {
		buffer := acquireReceiveBuffer(size)
		if buffer.Cap() < size {
			t.Fatalf("buffer(%d) has capacity %d", size, buffer.Cap())
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
	releaseFrameBuffer(make([]byte, 17))
	buffer := acquireFrameBuffer(256*1024 + 1)
	if len(buffer) != 256*1024+1 || cap(buffer) != 256*1024+1 {
		t.Fatalf("oversized frame has len/cap %d/%d", len(buffer), cap(buffer))
	}
}
