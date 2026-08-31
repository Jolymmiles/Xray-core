package mtproxy

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrFakeTLSReplay  = errors.New("mtproxy: fake TLS ClientRandom replay")
	ErrReplayCapacity = errors.New("mtproxy: fake TLS replay cache capacity reached")
)

type replayEntry struct {
	key       [16]byte
	expiresAt time.Time
}

// ReplayCache is a bounded exact cache. Cleanup is performed opportunistically
// during handshakes, so it owns no timer or background goroutine.
type ReplayCache struct {
	max int
	ttl time.Duration

	mu      sync.Mutex
	entries map[[16]byte]time.Time
	order   []replayEntry
	head    int
}

func NewReplayCache(maxEntries int, ttl time.Duration) (*ReplayCache, error) {
	if maxEntries <= 0 {
		return nil, fmt.Errorf("mtproxy: invalid replay cache capacity %d", maxEntries)
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("mtproxy: invalid replay cache TTL %s", ttl)
	}
	return &ReplayCache{
		max:     maxEntries,
		ttl:     ttl,
		entries: make(map[[16]byte]time.Time, maxEntries),
		order:   make([]replayEntry, 0, maxEntries),
	}, nil
}

func (c *ReplayCache) CheckAndAdd(key [16]byte, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeExpired(now)
	if expiresAt, found := c.entries[key]; found && expiresAt.After(now) {
		return ErrFakeTLSReplay
	}
	for len(c.entries) >= c.max {
		if !c.evictOldest() {
			return ErrReplayCapacity
		}
	}

	expiresAt := now.Add(c.ttl)
	c.entries[key] = expiresAt
	c.order = append(c.order, replayEntry{key: key, expiresAt: expiresAt})
	return nil
}

func (c *ReplayCache) evictOldest() bool {
	for c.head < len(c.order) {
		entry := c.order[c.head]
		c.head++
		if expiresAt, found := c.entries[entry.key]; found && expiresAt.Equal(entry.expiresAt) {
			delete(c.entries, entry.key)
			return true
		}
	}
	return false
}

func (c *ReplayCache) removeExpired(now time.Time) {
	for c.head < len(c.order) {
		entry := c.order[c.head]
		if entry.expiresAt.After(now) {
			break
		}
		if expiresAt, found := c.entries[entry.key]; found && expiresAt.Equal(entry.expiresAt) {
			delete(c.entries, entry.key)
		}
		c.head++
	}
	if c.head > 1024 && c.head*2 >= len(c.order) {
		copy(c.order, c.order[c.head:])
		c.order = c.order[:len(c.order)-c.head]
		c.head = 0
	}
}
