package dispatcher

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	featurestats "github.com/xtls/xray-core/features/stats"
)

type presenceTestPolicy struct {
	online bool
}

type presenceTestStatsManager struct {
	featurestats.NoopManager
	onlineMap featurestats.OnlineMap
}

func (m *presenceTestStatsManager) GetOrRegisterOnlineMap(string) (featurestats.OnlineMap, error) {
	return m.onlineMap, nil
}

func (m *presenceTestStatsManager) GetOnlineMap(string) featurestats.OnlineMap {
	return m.onlineMap
}

type recordingExactOnlineMap struct {
	generation   uint64
	next         uint64
	live         map[uint64]string
	acquireCalls int
	replaceCalls int
	releaseCalls int
}

func newRecordingExactOnlineMap() *recordingExactOnlineMap {
	return &recordingExactOnlineMap{generation: 1, live: make(map[uint64]string)}
}

func (m *recordingExactOnlineMap) OnlineMapGeneration() uint64 { return m.generation }
func (m *recordingExactOnlineMap) AcquireOnlineLease(ip string) uint64 {
	m.acquireCalls++
	m.next++
	m.live[m.next] = ip
	return m.next
}
func (m *recordingExactOnlineMap) ReplaceOnlineLeases(old []uint64, ip string, newCount int) ([]uint64, bool) {
	m.replaceCalls++
	if len(old) != newCount {
		return nil, false
	}
	for _, token := range old {
		if _, found := m.live[token]; !found {
			return nil, false
		}
	}
	for _, token := range old {
		delete(m.live, token)
	}
	replacements := make([]uint64, newCount)
	for index := range replacements {
		m.next++
		m.live[m.next] = ip
		replacements[index] = m.next
	}
	return replacements, true
}
func (m *recordingExactOnlineMap) ReleaseOnlineLease(token uint64) {
	if _, found := m.live[token]; !found {
		return
	}
	m.releaseCalls++
	delete(m.live, token)
}
func (m *recordingExactOnlineMap) Count() int {
	ips := make(map[string]bool)
	for _, ip := range m.live {
		ips[ip] = true
	}
	return len(ips)
}
func (m *recordingExactOnlineMap) AddIP(string)    {}
func (m *recordingExactOnlineMap) RemoveIP(string) {}
func (m *recordingExactOnlineMap) ForEach(fn func(string, int64) bool) {
	for ip := range onlineMapIPSet(m.live) {
		if !fn(ip, 0) {
			return
		}
	}
}

func onlineMapIPSet(live map[uint64]string) map[string]bool {
	ips := make(map[string]bool)
	for _, ip := range live {
		ips[ip] = true
	}
	return ips
}

type recordingLegacyOnlineMap struct {
	access sync.Mutex
	refs   map[string]int
	events []string
}

func newRecordingLegacyOnlineMap() *recordingLegacyOnlineMap {
	return &recordingLegacyOnlineMap{refs: make(map[string]int)}
}

func (m *recordingLegacyOnlineMap) AddIP(ip string) {
	m.access.Lock()
	m.refs[ip]++
	m.events = append(m.events, "add:"+ip)
	m.access.Unlock()
}

func (m *recordingLegacyOnlineMap) RemoveIP(ip string) {
	m.access.Lock()
	if m.refs[ip] > 1 {
		m.refs[ip]--
	} else {
		delete(m.refs, ip)
	}
	m.events = append(m.events, "remove:"+ip)
	m.access.Unlock()
}

func (m *recordingLegacyOnlineMap) Count() int {
	m.access.Lock()
	defer m.access.Unlock()
	return len(m.refs)
}

func (m *recordingLegacyOnlineMap) ForEach(fn func(string, int64) bool) {
	m.access.Lock()
	defer m.access.Unlock()
	for ip := range m.refs {
		if !fn(ip, 0) {
			return
		}
	}
}

func (m *recordingLegacyOnlineMap) resetEvents() {
	m.access.Lock()
	m.events = nil
	m.access.Unlock()
}

func (m *recordingLegacyOnlineMap) recordedEvents() []string {
	m.access.Lock()
	defer m.access.Unlock()
	return slices.Clone(m.events)
}

func (*presenceTestPolicy) Type() any                { return policy.ManagerType() }
func (*presenceTestPolicy) Start() error             { return nil }
func (*presenceTestPolicy) Close() error             { return nil }
func (*presenceTestPolicy) ForSystem() policy.System { return policy.System{} }
func (p *presenceTestPolicy) ForLevel(uint32) policy.Session {
	return policy.Session{Stats: policy.Stats{UserOnline: p.online}}
}

func TestPresenceTrackerActivatesAndClosesExactLease(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, manager)
	subject := session.PresenceSubject{
		Email: "alice@example.com",
		Level: 7,
		IP:    netip.MustParseAddr("192.0.2.1"),
	}

	reservation := tracker.Prepare(subject)
	metric := "user>>>alice@example.com>>>online"
	onlineMap := manager.GetOnlineMap(metric)
	if onlineMap == nil || onlineMap.Count() != 0 {
		t.Fatalf("prepare published online state: map=%v", onlineMap)
	}

	lease := reservation.Activate()
	if lease == nil {
		t.Fatal("activation returned nil lease")
	}
	assertOnlineMap(t, manager, metric, 1, "192.0.2.1")

	lease.Close()
	lease.Close()
	assertOnlineMap(t, manager, metric, 0)
}

func TestPresenceTrackerDisabledPolicyIsNoop(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tracker := newPresenceTracker(&presenceTestPolicy{online: false}, manager)
	reservation := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		Level: 7,
		IP:    netip.MustParseAddr("192.0.2.1"),
	})
	reservation.Activate().Close()

	if onlineMap := manager.GetOnlineMap("user>>>alice@example.com>>>online"); onlineMap != nil {
		t.Fatalf("disabled policy registered online map with count %d", onlineMap.Count())
	}
}

func TestPresenceTrackerUsesExactMapHandoff(t *testing.T) {
	onlineMap := newRecordingExactOnlineMap()
	manager := &presenceTestStatsManager{onlineMap: onlineMap}
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, manager)

	old := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("192.0.2.1"),
	}).Activate()
	replacement := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("198.51.100.2"),
	}).Handoff(old)

	if onlineMap.replaceCalls != 1 || onlineMap.acquireCalls != 1 || onlineMap.releaseCalls != 0 {
		t.Fatalf("exact calls: acquire=%d replace=%d release=%d; want 1/1/0",
			onlineMap.acquireCalls, onlineMap.replaceCalls, onlineMap.releaseCalls)
	}
	old.Close()
	if onlineMap.releaseCalls != 0 {
		t.Fatalf("stale old close released replacement: releases=%d", onlineMap.releaseCalls)
	}
	replacement.Close()
	if onlineMap.releaseCalls != 1 || len(onlineMap.live) != 0 {
		t.Fatalf("replacement close: releases=%d live=%v", onlineMap.releaseCalls, onlineMap.live)
	}
}

func TestPresenceTrackerUsesOneExactBatchHandoff(t *testing.T) {
	onlineMap := newRecordingExactOnlineMap()
	manager := &presenceTestStatsManager{onlineMap: onlineMap}
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, manager)
	old := make([]session.PresenceLease, 3)
	for index := range old {
		old[index] = tracker.Prepare(session.PresenceSubject{
			Email: "alice@example.com",
			IP:    netip.MustParseAddr("192.0.2.1"),
		}).Activate()
	}

	replacements := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("198.51.100.2"),
	}).HandoffAll(old)
	if len(replacements) != len(old) {
		t.Fatalf("replacement count = %d, want %d", len(replacements), len(old))
	}
	if onlineMap.replaceCalls != 1 || onlineMap.acquireCalls != len(old) || onlineMap.releaseCalls != 0 {
		t.Fatalf("exact calls: acquire=%d replace=%d release=%d; want %d/1/0",
			onlineMap.acquireCalls, onlineMap.replaceCalls, onlineMap.releaseCalls, len(old))
	}
	for _, lease := range old {
		lease.Close()
	}
	if onlineMap.releaseCalls != 0 {
		t.Fatalf("stale old batch close released replacements: releases=%d", onlineMap.releaseCalls)
	}
	for _, lease := range replacements {
		lease.Close()
	}
	if onlineMap.releaseCalls != len(old) || len(onlineMap.live) != 0 {
		t.Fatalf("replacement closes: releases=%d live=%v", onlineMap.releaseCalls, onlineMap.live)
	}
}

func TestPresenceTrackerDifferentGenerationFallsBackNewBeforeOld(t *testing.T) {
	oldMap := newRecordingExactOnlineMap()
	newMap := newRecordingExactOnlineMap()
	newMap.generation = 2
	policyManager := &presenceTestPolicy{online: true}
	oldTracker := newPresenceTracker(policyManager, &presenceTestStatsManager{onlineMap: oldMap})
	newTracker := newPresenceTracker(policyManager, &presenceTestStatsManager{onlineMap: newMap})

	old := oldTracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("192.0.2.1"),
	}).Activate()
	replacement := newTracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("198.51.100.2"),
	}).Handoff(old)

	if oldMap.replaceCalls != 0 || newMap.replaceCalls != 0 || newMap.acquireCalls != 1 || oldMap.releaseCalls != 1 {
		t.Fatalf("cross-generation calls: old replace/release=%d/%d new acquire/replace=%d/%d",
			oldMap.replaceCalls, oldMap.releaseCalls, newMap.acquireCalls, newMap.replaceCalls)
	}
	replacement.Close()
}

func TestPresenceTrackerPolicyDisabledHandoffClosesOldLease(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	enabled := newPresenceTracker(&presenceTestPolicy{online: true}, manager)
	disabled := newPresenceTracker(&presenceTestPolicy{online: false}, manager)
	subject := session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("192.0.2.1"),
	}
	old := enabled.Prepare(subject).Activate()
	disabled.Prepare(subject).Handoff(old).Close()
	assertOnlineMap(t, manager, "user>>>alice@example.com>>>online", 0)
}

func TestPresenceTrackerCustomBatchActivatesAllBeforeClosingOld(t *testing.T) {
	onlineMap := newRecordingLegacyOnlineMap()
	manager := &presenceTestStatsManager{onlineMap: onlineMap}
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, manager)
	old := make([]session.PresenceLease, 2)
	for index := range old {
		old[index] = tracker.Prepare(session.PresenceSubject{
			Email: "alice@example.com",
			IP:    netip.MustParseAddr("192.0.2.1"),
		}).Activate()
	}
	onlineMap.resetEvents()

	replacements := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("198.51.100.2"),
	}).HandoffAll(old)
	want := []string{
		"add:198.51.100.2", "add:198.51.100.2",
		"remove:192.0.2.1", "remove:192.0.2.1",
	}
	if got := onlineMap.recordedEvents(); !slices.Equal(got, want) {
		t.Fatalf("custom fallback order = %v, want %v", got, want)
	}
	for _, lease := range replacements {
		lease.Close()
	}
}

func TestPresenceReservationHasOneConcurrentTerminalWinner(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, manager)
	reservation := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("192.0.2.1"),
	})

	start := make(chan struct{})
	leases := make([]session.PresenceLease, 32)
	var wait sync.WaitGroup
	for index := range leases {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if index%2 == 0 {
				leases[index] = reservation.Activate()
			} else {
				reservation.Abort()
			}
		}()
	}
	close(start)
	wait.Wait()

	onlineMap := manager.GetOnlineMap("user>>>alice@example.com>>>online")
	if onlineMap == nil || onlineMap.Count() > 1 {
		t.Fatalf("concurrent terminal published more than one reference: map=%v", onlineMap)
	}
	for _, lease := range leases {
		if lease != nil {
			lease.Close()
		}
	}
	if onlineMap.Count() != 0 {
		t.Fatalf("online count after closing winner = %d, want 0", onlineMap.Count())
	}
}

func TestPresenceTrackerRateLimitsSanitizedFallbackWarning(t *testing.T) {
	onlineMap := newRecordingLegacyOnlineMap()
	tracker := newPresenceTracker(
		&presenceTestPolicy{online: true},
		&presenceTestStatsManager{onlineMap: onlineMap},
	)
	now := time.Unix(100, 0)
	tracker.warningNow = func() time.Time { return now }
	var warnings []string
	tracker.warningSink = func(message string) { warnings = append(warnings, message) }

	handoff := func() {
		old := tracker.Prepare(session.PresenceSubject{
			Email: "alice@example.com",
			IP:    netip.MustParseAddr("192.0.2.1"),
		}).Activate()
		tracker.Prepare(session.PresenceSubject{
			Email: "alice@example.com",
			IP:    netip.MustParseAddr("198.51.100.2"),
		}).Handoff(old).Close()
	}
	handoff()
	handoff()
	if len(warnings) != 1 {
		t.Fatalf("warnings inside rate window = %v, want one", warnings)
	}
	now = now.Add(time.Minute)
	handoff()
	if len(warnings) != 2 {
		t.Fatalf("warnings after rate window = %v, want two", warnings)
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "alice") || strings.Contains(warning, "192.0.2.1") || strings.Contains(warning, "198.51.100.2") {
			t.Fatalf("warning leaked subject data: %q", warning)
		}
	}
}

func assertOnlineMap(t *testing.T, manager featurestats.Manager, name string, count int, wantIPs ...string) {
	t.Helper()
	onlineMap := manager.GetOnlineMap(name)
	if onlineMap == nil {
		t.Fatalf("online map %q not found", name)
	}
	if got := onlineMap.Count(); got != count {
		t.Fatalf("online count = %d, want %d", got, count)
	}
	gotIPs := make(map[string]bool)
	onlineMap.ForEach(func(ip string, _ int64) bool {
		gotIPs[ip] = true
		return true
	})
	if len(gotIPs) != len(wantIPs) {
		t.Fatalf("online IPs = %v, want %v", gotIPs, wantIPs)
	}
	for _, ip := range wantIPs {
		if !gotIPs[ip] {
			t.Fatalf("online IPs = %v, missing %q", gotIPs, ip)
		}
	}
}
