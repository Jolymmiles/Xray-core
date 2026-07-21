// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"io"
	"math/bits"
	"sync"

	"github.com/xtls/xray-core/common/buf"
)

const (
	poolMinShift = 10
	poolClasses  = 7
)

var bufferPools [poolClasses + 1]sync.Pool

type receiveBuffer struct {
	xray  *buf.Buffer
	bytes []byte
}

func acquireReceiveBuffer(size int) receiveBuffer {
	if size <= buf.Size {
		return receiveBuffer{xray: buf.New()}
	}
	class := receivePoolClass(size)
	if class < 0 {
		return receiveBuffer{bytes: make([]byte, size)}
	}
	if pooled := bufferPools[class].Get(); pooled != nil {
		return receiveBuffer{bytes: pooledBytes(pooled, class, size)}
	}
	return receiveBuffer{bytes: make([]byte, size, 1<<(poolMinShift+class))}
}

func (buffer receiveBuffer) Len() int {
	if buffer.xray != nil {
		return int(buffer.xray.Len())
	}
	return len(buffer.bytes)
}

func (buffer receiveBuffer) Cap() int {
	if buffer.xray != nil {
		return int(buffer.xray.Cap())
	}
	return cap(buffer.bytes)
}

func (buffer receiveBuffer) IsEmpty() bool {
	return buffer.Len() == 0
}

func (buffer *receiveBuffer) readFullFrom(reader io.Reader, size int) error {
	if buffer.xray != nil {
		_, err := buffer.xray.ReadFullFrom(reader, int32(size))
		return err
	}
	_, err := io.ReadFull(reader, buffer.bytes)
	return err
}

func (buffer receiveBuffer) data(offset int) []byte {
	if buffer.xray != nil {
		return buffer.xray.BytesFrom(int32(offset))
	}
	return buffer.bytes[offset:]
}

func (buffer receiveBuffer) multiBuffer(offset int) buf.MultiBuffer {
	if buffer.xray != nil {
		buffer.xray.Advance(int32(offset))
		return buffer.xray.SingleMultiBuffer()
	}
	multiBuffer := buf.MergeBytes(nil, buffer.bytes[offset:])
	releaseReceiveBuffer(buffer)
	return multiBuffer
}

func releaseReceiveBuffer(buffer receiveBuffer) {
	if buffer.xray != nil {
		buffer.xray.Release()
		return
	}
	capacity := cap(buffer.bytes)
	if capacity < 1<<poolMinShift || capacity&(capacity-1) != 0 {
		return
	}
	class := bits.Len(uint(capacity)) - 1 - poolMinShift
	if class < 0 || class >= poolClasses {
		return
	}
	putPooledBytes(buffer.bytes, class)
}

func receivePoolClass(size int) int {
	if size < 0 {
		return -1
	}
	if size <= 1<<poolMinShift {
		return 0
	}
	class := bits.Len(uint(size-1)) - poolMinShift
	if class >= poolClasses {
		return -1
	}
	return class
}

func acquireFrameBuffer(size int) []byte {
	class := bufferPoolClass(size, poolClasses+1)
	if class < 0 {
		return make([]byte, size)
	}
	if pooled := bufferPools[class].Get(); pooled != nil {
		return pooledBytes(pooled, class, size)
	}
	return make([]byte, size, 1<<(poolMinShift+class))
}

func releaseFrameBuffer(buffer []byte) {
	capacity := cap(buffer)
	if capacity < 1<<poolMinShift || capacity&(capacity-1) != 0 {
		return
	}
	class := bits.Len(uint(capacity)) - 1 - poolMinShift
	if class < 0 || class >= len(bufferPools) {
		return
	}
	putPooledBytes(buffer, class)
}

func pooledBytes(pooled any, class, size int) []byte {
	switch class {
	case 0:
		return pooled.(*[1 << 10]byte)[:size]
	case 1:
		return pooled.(*[1 << 11]byte)[:size]
	case 2:
		return pooled.(*[1 << 12]byte)[:size]
	case 3:
		return pooled.(*[1 << 13]byte)[:size]
	case 4:
		return pooled.(*[1 << 14]byte)[:size]
	case 5:
		return pooled.(*[1 << 15]byte)[:size]
	case 6:
		return pooled.(*[1 << 16]byte)[:size]
	case 7:
		return pooled.(*[1 << 17]byte)[:size]
	default:
		panic("invalid SMUX buffer pool class")
	}
}

func putPooledBytes(buffer []byte, class int) {
	switch class {
	case 0:
		bufferPools[class].Put((*[1 << 10]byte)(buffer[:1<<10]))
	case 1:
		bufferPools[class].Put((*[1 << 11]byte)(buffer[:1<<11]))
	case 2:
		bufferPools[class].Put((*[1 << 12]byte)(buffer[:1<<12]))
	case 3:
		bufferPools[class].Put((*[1 << 13]byte)(buffer[:1<<13]))
	case 4:
		bufferPools[class].Put((*[1 << 14]byte)(buffer[:1<<14]))
	case 5:
		bufferPools[class].Put((*[1 << 15]byte)(buffer[:1<<15]))
	case 6:
		bufferPools[class].Put((*[1 << 16]byte)(buffer[:1<<16]))
	case 7:
		bufferPools[class].Put((*[1 << 17]byte)(buffer[:1<<17]))
	default:
		panic("invalid SMUX buffer pool class")
	}
}

func bufferPoolClass(size, classes int) int {
	if size < 0 {
		return -1
	}
	if size <= 1<<poolMinShift {
		return 0
	}
	class := bits.Len(uint(size-1)) - poolMinShift
	if class >= classes {
		return -1
	}
	return class
}
