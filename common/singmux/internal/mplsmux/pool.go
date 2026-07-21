// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"math/bits"
	"sync"
)

const (
	poolMinShift = 10
	poolClasses  = 7
)

var bufferPools [poolClasses + 1]sync.Pool

func acquireReceiveBuffer(size int) []byte {
	class := receivePoolClass(size)
	if class < 0 {
		return make([]byte, size)
	}
	if pooled := bufferPools[class].Get(); pooled != nil {
		return pooledBytes(pooled, class, size)
	}
	return make([]byte, size, 1<<(poolMinShift+class))
}

func releaseReceiveBuffer(buffer []byte) {
	capacity := cap(buffer)
	if capacity < 1<<poolMinShift || capacity&(capacity-1) != 0 {
		return
	}
	class := bits.Len(uint(capacity)) - 1 - poolMinShift
	if class < 0 || class >= poolClasses {
		return
	}
	putPooledBytes(buffer, class)
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
