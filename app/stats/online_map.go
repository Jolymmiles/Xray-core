package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	localhostIPv4 = "127.0.0.1"
	localhostIPv6 = "[::1]"
)

type ipEntry struct {
	legacyRefs int
	exactRefs  int
	lastSeen   int64
}

// OnlineMap is a refcount-based implementation of stats.OnlineMap.
// IPs are tracked by reference counting: AddIP increments, RemoveIP decrements.
// An IP is removed from the map when its reference count reaches zero.
type OnlineMap struct {
	entries    map[string]ipEntry
	leases     map[uint64]string
	access     sync.Mutex
	generation uint64
	nextToken  uint64
	count      atomic.Int64
}

var onlineMapGeneration atomic.Uint64

// NewOnlineMap creates a new OnlineMap instance.
func NewOnlineMap() *OnlineMap {
	return &OnlineMap{
		entries:    make(map[string]ipEntry),
		leases:     make(map[uint64]string),
		generation: nextOnlineMapGeneration(),
	}
}

func nextOnlineMapGeneration() uint64 {
	for {
		if generation := onlineMapGeneration.Add(1); generation != 0 {
			return generation
		}
	}
}

// AddIP implements stats.OnlineMap.
func (om *OnlineMap) AddIP(ip string) {
	if ip == localhostIPv4 || ip == localhostIPv6 {
		return
	}
	now := time.Now().Unix()
	om.access.Lock()
	defer om.access.Unlock()
	if e, ok := om.entries[ip]; ok {
		e.legacyRefs++
		e.lastSeen = now
		om.entries[ip] = e
	} else {
		om.entries[ip] = ipEntry{
			legacyRefs: 1,
			lastSeen:   now,
		}
		om.count.Add(1)
	}
}

// RemoveIP implements stats.OnlineMap.
func (om *OnlineMap) RemoveIP(ip string) {
	om.access.Lock()
	defer om.access.Unlock()
	e, ok := om.entries[ip]
	if !ok || e.legacyRefs == 0 {
		return
	}
	e.legacyRefs--
	if e.legacyRefs+e.exactRefs == 0 {
		delete(om.entries, ip)
		om.count.Add(-1)
	} else {
		om.entries[ip] = e
	}
}

// OnlineMapGeneration identifies this concrete map instance.
func (om *OnlineMap) OnlineMapGeneration() uint64 {
	return om.generation
}

// AcquireOnlineLease adds one exact reference and returns its ownership token.
func (om *OnlineMap) AcquireOnlineLease(ip string) uint64 {
	if ip == "" || ip == localhostIPv4 || ip == localhostIPv6 {
		return 0
	}

	now := time.Now().Unix()
	om.access.Lock()
	defer om.access.Unlock()

	token := om.nextTokenLocked()
	om.leases[token] = ip

	entry, exists := om.entries[ip]
	entry.exactRefs++
	entry.lastSeen = now
	om.entries[ip] = entry
	if !exists {
		om.count.Add(1)
	}
	return token
}

// ReplaceOnlineLeases atomically consumes old exact tokens and creates the
// same number of fresh references for ip. Validation failure changes nothing.
func (om *OnlineMap) ReplaceOnlineLeases(old []uint64, ip string, newCount int) ([]uint64, bool) {
	if newCount != len(old) || (newCount > 0 && (ip == "" || ip == localhostIPv4 || ip == localhostIPv6)) {
		return nil, false
	}
	if newCount == 0 {
		return nil, true
	}

	om.access.Lock()
	defer om.access.Unlock()

	seen := make(map[uint64]struct{}, len(old))
	for _, token := range old {
		if token == 0 {
			return nil, false
		}
		if _, duplicate := seen[token]; duplicate {
			return nil, false
		}
		if _, exists := om.leases[token]; !exists {
			return nil, false
		}
		seen[token] = struct{}{}
	}

	visibleBefore := len(om.entries)
	for _, token := range old {
		oldIP := om.leases[token]
		delete(om.leases, token)
		entry := om.entries[oldIP]
		entry.exactRefs--
		if entry.legacyRefs+entry.exactRefs == 0 {
			delete(om.entries, oldIP)
		} else {
			om.entries[oldIP] = entry
		}
	}

	now := time.Now().Unix()
	replacements := make([]uint64, newCount)
	entry := om.entries[ip]
	entry.exactRefs += newCount
	entry.lastSeen = now
	om.entries[ip] = entry
	for index := range replacements {
		token := om.nextTokenLocked()
		om.leases[token] = ip
		replacements[index] = token
	}
	om.count.Add(int64(len(om.entries) - visibleBefore))
	return replacements, true
}

// ReleaseOnlineLease removes only the exact reference owned by token.
func (om *OnlineMap) ReleaseOnlineLease(token uint64) {
	if token == 0 {
		return
	}

	om.access.Lock()
	defer om.access.Unlock()
	ip, exists := om.leases[token]
	if !exists {
		return
	}
	delete(om.leases, token)

	entry := om.entries[ip]
	entry.exactRefs--
	if entry.legacyRefs+entry.exactRefs == 0 {
		delete(om.entries, ip)
		om.count.Add(-1)
		return
	}
	om.entries[ip] = entry
}

func (om *OnlineMap) nextTokenLocked() uint64 {
	om.nextToken++
	if om.nextToken == 0 {
		om.nextToken++
	}
	return om.nextToken
}

// Count implements stats.OnlineMap.
func (om *OnlineMap) Count() int {
	return int(om.count.Load())
}

// ForEach calls fn for each online IP. If fn returns false, iteration stops.
func (om *OnlineMap) ForEach(fn func(string, int64) bool) {
	om.access.Lock()
	defer om.access.Unlock()
	for ip, e := range om.entries {
		if !fn(ip, e.lastSeen) {
			break
		}
	}
}
