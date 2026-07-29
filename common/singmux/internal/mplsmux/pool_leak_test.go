// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"bytes"
	"math/bits"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// poolClassOfCapacity restates the classification both release paths perform on
// cap(buffer). It is deliberately a copy rather than a call into pool.go: these
// tests pin the *acquire* side of the contract, and a buffer is only returned to
// bufferPools when the capacity acquire produced lands inside the class range the
// matching release accepts. Restating the formula is what makes the assertion a
// contract check instead of a tautology over the function under test.
func poolClassOfCapacity(capacity int) int {
	if capacity < 1<<poolMinShift || capacity&(capacity-1) != 0 {
		return -1
	}
	return bits.Len(uint(capacity)) - 1 - poolMinShift
}

// receiveFrameSizes covers every class transition a carrier frame can drive.
// readLoop skips zero-length frames and frameHeader.length is a uint16, so the
// reachable receive payload range is exactly 1..maxFramePayload.
var receiveFrameSizes = []int{
	1, 1024, 1025, buf.Size - 1, buf.Size, buf.Size + 1,
	16383, 16384, 16385, 32767, 32768, 32769, 65534, maxFramePayload,
}

// TestAcquiredReceiveBufferIsAlwaysReleasable proves no receive buffer is silently
// dropped: for every reachable frame size, acquireReceiveBuffer yields either an
// xray buffer (released through buf.Buffer.Release) or a byte slice whose capacity
// falls in the class range releaseReceiveBuffer accepts (0..poolClasses-1).
func TestAcquiredReceiveBufferIsAlwaysReleasable(t *testing.T) {
	for _, size := range receiveFrameSizes {
		buffer := acquireReceiveBuffer(size)
		if buffer.Cap() < size {
			t.Fatalf("acquireReceiveBuffer(%d) capacity %d is short", size, buffer.Cap())
		}
		switch {
		case size <= buf.Size:
			if buffer.xray == nil {
				t.Fatalf("acquireReceiveBuffer(%d) did not use an xray buffer", size)
			}
			if buffer.bytes != nil {
				t.Fatalf("acquireReceiveBuffer(%d) returned both backings", size)
			}
		default:
			if buffer.xray != nil {
				t.Fatalf("acquireReceiveBuffer(%d) used an xray buffer above buf.Size", size)
			}
			if len(buffer.bytes) != size {
				t.Fatalf("acquireReceiveBuffer(%d) length is %d", size, len(buffer.bytes))
			}
			class := poolClassOfCapacity(cap(buffer.bytes))
			if class < 0 || class >= poolClasses {
				t.Fatalf("acquireReceiveBuffer(%d) capacity %d maps to class %d, which releaseReceiveBuffer drops",
					size, cap(buffer.bytes), class)
			}
		}
		releaseReceiveBuffer(buffer)
	}
}

// TestAcquiredFrameBufferIsAlwaysReleasable is the same proof for the write path.
// Frame buffers carry an 8-byte header on top of the payload, so their top class
// is one above the receive path's — bufferPools has poolClasses+1 entries for
// exactly that reason.
func TestAcquiredFrameBufferIsAlwaysReleasable(t *testing.T) {
	sizes := []int{
		frameHeaderSize, 1024, 1025, 2048, 4096, 8192, 16384, 32768, 65536,
		frameHeaderSize + maxFramePayload,
	}
	for _, size := range sizes {
		buffer := acquireFrameBuffer(size)
		if len(buffer) != size {
			t.Fatalf("acquireFrameBuffer(%d) length is %d", size, len(buffer))
		}
		class := poolClassOfCapacity(cap(buffer))
		if class < 0 || class >= len(bufferPools) {
			t.Fatalf("acquireFrameBuffer(%d) capacity %d maps to class %d, which releaseFrameBuffer drops",
				size, cap(buffer), class)
		}
		releaseFrameBuffer(buffer)
	}
}

// TestReceivePathNeverReachesTopPoolClass pins the asymmetry between the two
// release guards as intentional rather than a mismatch. receiveFrameSizes is
// bounded by the uint16 length field, and validateConfig refuses any MaxFrameSize
// above it, so a receive buffer can never be classified into the top pool class
// that only frame buffers use.
func TestReceivePathNeverReachesTopPoolClass(t *testing.T) {
	if got := receivePoolClass(maxFramePayload); got != poolClasses-1 {
		t.Fatalf("largest receive payload maps to class %d, want %d", got, poolClasses-1)
	}
	if got := bufferPoolClass(frameHeaderSize+maxFramePayload, poolClasses+1); got != poolClasses {
		t.Fatalf("largest frame maps to class %d, want %d", got, poolClasses)
	}
	oversized := DefaultConfig()
	oversized.MaxFrameSize = maxFramePayload + 1
	if err := validateConfig(oversized); err == nil {
		t.Fatal("validateConfig accepted a frame size above the uint16 length field")
	}
}

// TestReceiveAcquireNeverUsesAClassReleaseRejects closes the ceiling that the
// reachable-size sweep cannot see. releaseReceiveBuffer returns buffers only for
// classes below poolClasses, so the moment receivePoolClass admits the top class
// every such buffer is taken from bufferPools and never put back — a one-way pool
// drain rather than a plain missed reuse. The sizes here run past the uint16 wire
// limit on purpose: this guards the invariant, not today's reachability.
func TestReceiveAcquireNeverUsesAClassReleaseRejects(t *testing.T) {
	for class := range len(bufferPools) + 2 {
		for _, size := range []int{1 << (poolMinShift + class), 1<<(poolMinShift+class) + 1} {
			got := receivePoolClass(size)
			if got >= poolClasses {
				t.Fatalf("receivePoolClass(%d) = %d, but releaseReceiveBuffer only returns classes below %d",
					size, got, poolClasses)
			}
		}
	}
}

// TestPooledClassesRoundTripWithoutPanic exercises putPooledBytes and pooledBytes
// across every class the pool array declares. A Get may legitimately miss, in
// which case acquire allocates fresh at the same capacity, so nothing here depends
// on sync.Pool retention — only on the two switches agreeing with bufferPools.
func TestPooledClassesRoundTripWithoutPanic(t *testing.T) {
	for class := range len(bufferPools) {
		size := 1 << (poolMinShift + class)
		first := acquireFrameBuffer(size)
		if cap(first) != size {
			t.Fatalf("class %d acquired capacity %d, want %d", class, cap(first), size)
		}
		releaseFrameBuffer(first)
		second := acquireFrameBuffer(size)
		if cap(second) != size || len(second) != size {
			t.Fatalf("class %d re-acquired len/cap %d/%d, want %d/%d", class, len(second), cap(second), size, size)
		}
		releaseFrameBuffer(second)
	}
}

// TestUnpooledSizesAreNotMisclassified guards the other direction: a buffer that
// was never taken from a pool must not be handed to putPooledBytes. Sizes above
// the top class allocate at exact capacity, and a power-of-two capacity there
// still has to be rejected by both release paths.
func TestUnpooledSizesAreNotMisclassified(t *testing.T) {
	for _, size := range []int{1 << 18, 1<<18 + 1} {
		buffer := acquireFrameBuffer(size)
		if cap(buffer) != size {
			t.Fatalf("acquireFrameBuffer(%d) capacity is %d", size, cap(buffer))
		}
		if class := poolClassOfCapacity(cap(buffer)); class >= 0 && class < len(bufferPools) {
			t.Fatalf("oversized frame %d maps into pool class %d", size, class)
		}
		releaseFrameBuffer(buffer)
	}
	// A receive payload can never be this large, but the guard must still hold if
	// the length field ever widens.
	if class := poolClassOfCapacity(1 << (poolMinShift + poolClasses)); class < poolClasses {
		t.Fatalf("top frame class %d is below the receive ceiling %d", class, poolClasses)
	}
}

// fillReceiveBuffer loads payload the way readLoop does (session.go:377-378), so
// the ownership tests below see exactly the state multiBuffer() meets in
// production rather than a hand-built one.
func fillReceiveBuffer(t *testing.T, payload []byte) receiveBuffer {
	t.Helper()
	buffer := acquireReceiveBuffer(len(payload))
	if err := buffer.readFullFrom(bytes.NewReader(payload), len(payload)); err != nil {
		t.Fatalf("readFullFrom(%d) failed: %v", len(payload), err)
	}
	return buffer
}

func countingPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

func flattenMultiBuffer(multi buf.MultiBuffer) []byte {
	var flat []byte
	for _, buffer := range multi {
		flat = append(flat, buffer.Bytes()...)
	}
	return flat
}

// TestMultiBufferTransfersXrayOwnershipToCaller pins the first half of the D7
// trap. At or below buf.Size, multiBuffer() hands the *buf.Buffer itself to the
// caller through SingleMultiBuffer() and must NOT release it — the returned
// MultiBuffer is the only remaining reference. buf.Buffer has no refcount, so a
// stray release here is silent memory corruption rather than a detectable error.
// Release() does *b = Buffer{}, so asserting identity plus live content is what
// makes a "normalized" release on this path fail loudly.
func TestMultiBufferTransfersXrayOwnershipToCaller(t *testing.T) {
	const offset = 16
	payload := countingPayload(1024)
	buffer := fillReceiveBuffer(t, payload)
	if buffer.xray == nil {
		t.Fatalf("payload of %d bytes did not take the xray path", len(payload))
	}
	owned := buffer.xray

	multi := buffer.multiBuffer(offset)
	defer buf.ReleaseMulti(multi)

	if len(multi) != 1 || multi[0] != owned {
		t.Fatal("xray path did not transfer the original buf.Buffer to the caller")
	}
	if got := multi[0].Len(); got != int32(len(payload)-offset) {
		t.Fatalf("transferred buffer holds %d bytes, want %d — a release on this path zeroes it",
			got, len(payload)-offset)
	}
	if !bytes.Equal(flattenMultiBuffer(multi), payload[offset:]) {
		t.Fatal("transferred buffer content does not match the payload after the offset")
	}
}

// TestMultiBufferCopiesAndReleasesPooledBytes pins the second half. Above
// buf.Size the payload lives in a pooled []byte, so multiBuffer() copies it via
// MergeBytes and releases the pooled array internally (pool.go:79). The returned
// MultiBuffer must therefore not alias that array: if it did, the internal
// release would have handed a live buffer back to bufferPools and the next
// acquirer would overwrite the caller's data.
func TestMultiBufferCopiesAndReleasesPooledBytes(t *testing.T) {
	const offset = 16
	payload := countingPayload(16 * 1024)
	buffer := fillReceiveBuffer(t, payload)
	if buffer.bytes == nil {
		t.Fatalf("payload of %d bytes did not take the pooled bytes path", len(payload))
	}
	pooled := buffer.bytes

	multi := buffer.multiBuffer(offset)
	defer buf.ReleaseMulti(multi)

	if !bytes.Equal(flattenMultiBuffer(multi), payload[offset:]) {
		t.Fatal("copied content does not match the payload after the offset")
	}
	if first := multi[0].Bytes(); &first[0] == &pooled[offset] {
		t.Fatal("bytes path aliased the pooled array it had already returned to the pool")
	}
}
