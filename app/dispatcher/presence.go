package dispatcher

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
)

type exactOnlineMap interface {
	OnlineMapGeneration() uint64
	AcquireOnlineLease(string) uint64
	ReplaceOnlineLeases([]uint64, string, int) ([]uint64, bool)
	ReleaseOnlineLease(uint64)
}

type presenceTracker struct {
	policy      policy.Manager
	stats       stats.Manager
	warningNow  func() time.Time
	warningSink func(string)
	lastWarning atomic.Int64
}

func newPresenceTracker(policyManager policy.Manager, statsManager stats.Manager) *presenceTracker {
	return &presenceTracker{
		policy:     policyManager,
		stats:      statsManager,
		warningNow: time.Now,
		warningSink: func(message string) {
			errors.LogWarning(context.Background(), message)
		},
	}
}

func (t *presenceTracker) Prepare(subject session.PresenceSubject) session.PresenceReservation {
	if t == nil || t.policy == nil || t.stats == nil || subject.Email == "" || !validPresenceIP(subject.IP) {
		return noopDispatcherPresence
	}
	if !t.policy.ForLevel(subject.Level).Stats.UserOnline {
		return noopDispatcherPresence
	}
	onlineMap, err := t.stats.GetOrRegisterOnlineMap("user>>>" + subject.Email + ">>>online")
	if err != nil || onlineMap == nil {
		t.warnDegraded("online map unavailable")
		return noopDispatcherPresence
	}
	return &presenceReservation{
		onlineMap: onlineMap,
		exactMap:  exactMapFromOnlineMap(onlineMap),
		ip:        formatPresenceIP(subject.IP),
		warning:   t.warnDegraded,
	}
}

func (t *presenceTracker) warnDegraded(reason string) {
	if t == nil || t.warningNow == nil || t.warningSink == nil {
		return
	}
	now := t.warningNow().UnixNano()
	for {
		last := t.lastWarning.Load()
		if last != 0 && now-last < int64(time.Minute) {
			return
		}
		if t.lastWarning.CompareAndSwap(last, now) {
			t.warningSink("online presence degraded: " + reason)
			return
		}
	}
}

func validPresenceIP(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLoopback()
}

func formatPresenceIP(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is6() {
		return "[" + ip.String() + "]"
	}
	return ip.String()
}

func exactMapFromOnlineMap(onlineMap stats.OnlineMap) exactOnlineMap {
	exactMap, _ := onlineMap.(exactOnlineMap)
	return exactMap
}

type presenceReservation struct {
	onlineMap stats.OnlineMap
	exactMap  exactOnlineMap
	ip        string
	warning   func(string)
	terminal  atomic.Bool
}

func (r *presenceReservation) Activate() session.PresenceLease {
	if r == nil || !r.terminal.CompareAndSwap(false, true) {
		return noopDispatcherPresence
	}
	return r.activate()
}

func (r *presenceReservation) Handoff(old session.PresenceLease) session.PresenceLease {
	if r == nil || !r.terminal.CompareAndSwap(false, true) {
		return noopDispatcherPresence
	}
	if oldLease, ok := old.(*presenceLease); ok && r.exactMap != nil && oldLease.exactMap != nil &&
		oldLease.generation == r.exactMap.OnlineMapGeneration() && oldLease.closed.CompareAndSwap(false, true) {
		if tokens, replaced := r.exactMap.ReplaceOnlineLeases([]uint64{oldLease.token}, r.ip, 1); replaced && len(tokens) == 1 && tokens[0] != 0 {
			return &presenceLease{exactMap: r.exactMap, generation: oldLease.generation, token: tokens[0]}
		}
		r.warnAtomicFallback()
		lease := r.activate()
		oldLease.exactMap.ReleaseOnlineLease(oldLease.token)
		return lease
	}
	if isRealPresenceLease(old) {
		r.warnAtomicFallback()
	}
	lease := r.activate()
	if old != nil {
		old.Close()
	}
	return lease
}

func (r *presenceReservation) HandoffAll(old []session.PresenceLease) []session.PresenceLease {
	if r == nil || !r.terminal.CompareAndSwap(false, true) {
		return noopPresenceLeases(len(old))
	}
	if len(old) == 0 {
		return nil
	}

	frozen := make([]bool, len(old))
	exactLeases := make([]*presenceLease, len(old))
	exactTokens := make([]uint64, len(old))
	canReplace := r.exactMap != nil
	if canReplace {
		generation := r.exactMap.OnlineMapGeneration()
		for index, lease := range old {
			exactLease, ok := lease.(*presenceLease)
			if !ok || exactLease.exactMap == nil || exactLease.generation != generation || exactLease.closed.Load() {
				canReplace = false
				break
			}
			exactLeases[index] = exactLease
			exactTokens[index] = exactLease.token
		}
	}
	if canReplace {
		for index, lease := range exactLeases {
			if !lease.closed.CompareAndSwap(false, true) {
				canReplace = false
				break
			}
			frozen[index] = true
		}
	}
	if canReplace {
		tokens, replaced := r.exactMap.ReplaceOnlineLeases(exactTokens, r.ip, len(old))
		if replaced && validReplacementTokens(tokens, len(old)) {
			replacements := make([]session.PresenceLease, len(tokens))
			generation := r.exactMap.OnlineMapGeneration()
			for index, token := range tokens {
				replacements[index] = &presenceLease{exactMap: r.exactMap, generation: generation, token: token}
			}
			return replacements
		}
		if replaced {
			for _, token := range tokens {
				r.exactMap.ReleaseOnlineLease(token)
			}
		}
	}
	if hasRealPresenceLease(old) {
		r.warnAtomicFallback()
	}

	replacements := make([]session.PresenceLease, len(old))
	for index := range replacements {
		replacements[index] = r.activate()
	}
	for index, lease := range old {
		if frozen[index] {
			exactLeases[index].exactMap.ReleaseOnlineLease(exactLeases[index].token)
			continue
		}
		if lease != nil {
			lease.Close()
		}
	}
	return replacements
}

func (r *presenceReservation) warnAtomicFallback() {
	if r.warning != nil {
		r.warning("atomic handoff unavailable")
	}
}

func isRealPresenceLease(lease session.PresenceLease) bool {
	_, ok := lease.(*presenceLease)
	return ok
}

func hasRealPresenceLease(leases []session.PresenceLease) bool {
	for _, lease := range leases {
		if isRealPresenceLease(lease) {
			return true
		}
	}
	return false
}

func validReplacementTokens(tokens []uint64, want int) bool {
	if len(tokens) != want {
		return false
	}
	for _, token := range tokens {
		if token == 0 {
			return false
		}
	}
	return true
}

func (r *presenceReservation) Abort() {
	if r != nil {
		r.terminal.CompareAndSwap(false, true)
	}
}

func (r *presenceReservation) activate() session.PresenceLease {
	if r.exactMap != nil {
		token := r.exactMap.AcquireOnlineLease(r.ip)
		if token == 0 {
			return noopDispatcherPresence
		}
		return &presenceLease{exactMap: r.exactMap, generation: r.exactMap.OnlineMapGeneration(), token: token}
	}
	r.onlineMap.AddIP(r.ip)
	return &presenceLease{onlineMap: r.onlineMap, ip: r.ip}
}

type presenceLease struct {
	onlineMap  stats.OnlineMap
	exactMap   exactOnlineMap
	generation uint64
	token      uint64
	ip         string
	closed     atomic.Bool
}

func (l *presenceLease) Close() {
	if l == nil || !l.closed.CompareAndSwap(false, true) {
		return
	}
	if l.exactMap != nil {
		l.exactMap.ReleaseOnlineLease(l.token)
		return
	}
	l.onlineMap.RemoveIP(l.ip)
}

type noopDispatcherPresenceType struct{}

var noopDispatcherPresence noopDispatcherPresenceType

func (noopDispatcherPresenceType) Activate() session.PresenceLease { return noopDispatcherPresence }
func (noopDispatcherPresenceType) Handoff(old session.PresenceLease) session.PresenceLease {
	if old != nil {
		old.Close()
	}
	return noopDispatcherPresence
}
func (noopDispatcherPresenceType) HandoffAll(old []session.PresenceLease) []session.PresenceLease {
	for _, lease := range old {
		if lease != nil {
			lease.Close()
		}
	}
	return noopPresenceLeases(len(old))
}
func (noopDispatcherPresenceType) Abort() {}
func (noopDispatcherPresenceType) Close() {}

func noopPresenceLeases(count int) []session.PresenceLease {
	if count == 0 {
		return nil
	}
	leases := make([]session.PresenceLease, count)
	for index := range leases {
		leases[index] = noopDispatcherPresence
	}
	return leases
}
