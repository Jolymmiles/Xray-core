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
	refCount int
	lastSeen int64
}

// OnlineMap is a refcount-based implementation of stats.OnlineMap.
// IPs are tracked by reference counting: AddIP increments, RemoveIP decrements.
// An IP is removed from the map when its reference count reaches zero.
type OnlineMap struct {
	entries map[string]ipEntry
	access  sync.Mutex
	count   atomic.Int64
}

// NewOnlineMap creates a new OnlineMap instance.
func NewOnlineMap() *OnlineMap {
	return &OnlineMap{
		entries: make(map[string]ipEntry),
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
		e.refCount++
		e.lastSeen = now
		om.entries[ip] = e
	} else {
		om.entries[ip] = ipEntry{
			refCount: 1,
			lastSeen: now,
		}
		om.count.Add(1)
	}
}

// RemoveIP implements stats.OnlineMap.
func (om *OnlineMap) RemoveIP(ip string) {
	om.access.Lock()
	defer om.access.Unlock()
	e, ok := om.entries[ip]
	if !ok {
		return
	}
	e.refCount--
	if e.refCount <= 0 {
		delete(om.entries, ip)
		om.count.Add(-1)
	} else {
		om.entries[ip] = e
	}
}

// HandoffIP atomically transfers one reference from oldIP to newIP.
// It is an internal capability used by structural online-presence tracking.
func (om *OnlineMap) HandoffIP(oldIP, newIP string) {
	now := time.Now().Unix()
	om.access.Lock()
	defer om.access.Unlock()
	if oldIP == newIP {
		if entry, found := om.entries[oldIP]; found {
			entry.lastSeen = now
			om.entries[oldIP] = entry
		}
		return
	}
	if oldEntry, found := om.entries[oldIP]; found {
		oldEntry.refCount--
		if oldEntry.refCount <= 0 {
			delete(om.entries, oldIP)
			om.count.Add(-1)
		} else {
			om.entries[oldIP] = oldEntry
		}
	}
	if newEntry, found := om.entries[newIP]; found {
		newEntry.refCount++
		newEntry.lastSeen = now
		om.entries[newIP] = newEntry
	} else {
		om.entries[newIP] = ipEntry{refCount: 1, lastSeen: now}
		om.count.Add(1)
	}
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
