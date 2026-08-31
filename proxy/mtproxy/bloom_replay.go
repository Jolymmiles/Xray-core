package mtproxy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	bloomBitsPerEntry = 15
	bloomHashCount    = 10
)

// BloomReplayCache keeps two fixed-size time windows. The previous window
// prevents boundary replays while the current window receives new keys. Memory
// is allocated once and never grows with connection count.
type BloomReplayCache struct {
	rotation time.Duration
	bitCount uint64

	mu          sync.Mutex
	windowStart time.Time
	current     []uint64
	previous    []uint64
}

func NewBloomReplayCache(capacity int, rotation time.Duration) (*BloomReplayCache, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("mtproxy: invalid Bloom replay capacity %d", capacity)
	}
	if rotation <= 0 {
		return nil, fmt.Errorf("mtproxy: invalid Bloom replay rotation %s", rotation)
	}
	bits := uint64(capacity * bloomBitsPerEntry)
	words := (bits + 63) / 64
	bits = words * 64
	return &BloomReplayCache{
		rotation: rotation,
		bitCount: bits,
		current:  make([]uint64, words),
		previous: make([]uint64, words),
	}, nil
}

func (c *BloomReplayCache) CheckAndAdd(key [16]byte, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rotate(now)

	digest := sha256.Sum256(key[:])
	first := binary.LittleEndian.Uint64(digest[0:8])
	step := binary.LittleEndian.Uint64(digest[8:16]) | 1
	if c.contains(c.current, first, step) || c.contains(c.previous, first, step) {
		return ErrFakeTLSReplay
	}
	c.add(c.current, first, step)
	return nil
}

func (c *BloomReplayCache) MemoryBytes() int {
	return (len(c.current) + len(c.previous)) * 8
}

func (c *BloomReplayCache) rotate(now time.Time) {
	if c.windowStart.IsZero() {
		c.windowStart = now
		return
	}
	if now.Before(c.windowStart) {
		return
	}
	steps := int64(now.Sub(c.windowStart) / c.rotation)
	if steps == 0 {
		return
	}
	if steps == 1 {
		c.current, c.previous = c.previous, c.current
		clear(c.current)
		c.windowStart = c.windowStart.Add(c.rotation)
		return
	}
	clear(c.current)
	clear(c.previous)
	c.windowStart = now
}

func (c *BloomReplayCache) contains(filter []uint64, first, step uint64) bool {
	for index := uint64(0); index < bloomHashCount; index++ {
		bit := (first + index*step) % c.bitCount
		if filter[bit>>6]&(uint64(1)<<(bit&63)) == 0 {
			return false
		}
	}
	return true
}

func (c *BloomReplayCache) add(filter []uint64, first, step uint64) {
	for index := uint64(0); index < bloomHashCount; index++ {
		bit := (first + index*step) % c.bitCount
		filter[bit>>6] |= uint64(1) << (bit & 63)
	}
}
