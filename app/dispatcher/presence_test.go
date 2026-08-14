package dispatcher

import (
	"context"
	"errors"
	"net/netip"
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
	err       error
}

func (m *presenceTestStatsManager) GetOrRegisterOnlineMap(string) (featurestats.OnlineMap, error) {
	return m.onlineMap, m.err
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

func (m *recordingExactOnlineMap) AddIP(ip string) {
	m.next++
	m.live[m.next] = ip
}
func (m *recordingExactOnlineMap) RemoveIP(string)             {}
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

func (m *recordingExactOnlineMap) ForEach(fn func(string, int64) bool) {
	for ip := range onlineMapIPSet(m.live) {
		if !fn(ip, 0) {
			return
		}
	}
}

type recordingLegacyOnlineMap struct {
	refs   map[string]int
	events []string
}

func newRecordingLegacyOnlineMap() *recordingLegacyOnlineMap {
	return &recordingLegacyOnlineMap{refs: make(map[string]int)}
}

func (m *recordingLegacyOnlineMap) AddIP(ip string) {
	m.events = append(m.events, "add "+ip)
	m.refs[ip]++
}

func (m *recordingLegacyOnlineMap) RemoveIP(ip string) {
	m.events = append(m.events, "remove "+ip)
	if m.refs[ip] <= 1 {
		delete(m.refs, ip)
		return
	}
	m.refs[ip]--
}
func (m *recordingLegacyOnlineMap) Count() int { return len(m.refs) }
func (m *recordingLegacyOnlineMap) ForEach(fn func(string, int64) bool) {
	for ip := range m.refs {
		if !fn(ip, 0) {
			return
		}
	}
}

var _ featurestats.OnlineMap = (*recordingLegacyOnlineMap)(nil)

func onlineMapIPSet(live map[uint64]string) map[string]bool {
	ips := make(map[string]bool)
	for _, ip := range live {
		ips[ip] = true
	}
	return ips
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

func TestPresenceTrackerStatsLookupFailureWarnsOnceWithoutSubjectData(t *testing.T) {
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, &presenceTestStatsManager{err: errors.New("lookup failed")})
	now := time.Unix(100, 0)
	tracker.warningNow = func() time.Time { return now }
	var warnings []string
	tracker.warningSink = func(message string) { warnings = append(warnings, message) }
	subject := session.PresenceSubject{
		Email:        "alice@example.com",
		IP:           netip.MustParseAddr("192.0.2.1"),
		PrincipalKey: [32]byte{0xde, 0xad, 0xbe, 0xef},
	}
	tracker.Prepare(subject).Activate().Close()
	tracker.Prepare(subject).Activate().Close()
	if len(warnings) != 1 {
		t.Fatalf("lookup warnings = %v, want one", warnings)
	}
	for _, secret := range []string{subject.Email, subject.IP.String(), "deadbeef"} {
		if strings.Contains(warnings[0], secret) {
			t.Fatalf("warning leaked %q: %q", secret, warnings[0])
		}
	}
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

func TestPresenceTrackerAlternativeExactShapeUsesDegradedFallback(t *testing.T) {
	onlineMap := newRecordingExactOnlineMap()
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, &presenceTestStatsManager{onlineMap: onlineMap})
	old := tracker.Prepare(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.1")}).Activate()
	oldLease, ok := old.(*presenceLease)
	if !ok || oldLease.exactMap != nil || oldLease.onlineMap != onlineMap {
		t.Fatalf("alternative map acquired private exact capability: %#v", old)
	}
	replacement := tracker.Prepare(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("198.51.100.2")}).Handoff(old)
	replacementLease, ok := replacement.(*presenceLease)
	if !ok || replacementLease.exactMap != nil || replacementLease.onlineMap != onlineMap {
		t.Fatalf("alternative map handoff acquired private exact capability: %#v", replacement)
	}
	if onlineMap.replaceCalls != 0 {
		t.Fatalf("alternative map exact replacements = %d, want 0", onlineMap.replaceCalls)
	}
	replacement.Close()
}

func TestPresenceTrackerUsesExactMapHandoff(t *testing.T) {
	onlineMap := appstats.NewOnlineMap()
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, &presenceTestStatsManager{onlineMap: onlineMap})

	old := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("192.0.2.1"),
	}).Activate()
	oldLease := old.(*presenceLease)
	replacement := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("198.51.100.2"),
	}).Handoff(old)
	replacementLease := replacement.(*presenceLease)

	if oldLease.exactMap != onlineMap || replacementLease.exactMap != onlineMap || !oldLease.closed.Load() {
		t.Fatalf("exact handoff leases: old=%#v replacement=%#v", oldLease, replacementLease)
	}
	if oldLease.token == 0 || replacementLease.token == 0 || oldLease.token == replacementLease.token {
		t.Fatalf("exact handoff tokens: old=%d replacement=%d", oldLease.token, replacementLease.token)
	}
	assertOnlineMapValue(t, onlineMap, 1, "198.51.100.2")
	old.Close()
	assertOnlineMapValue(t, onlineMap, 1, "198.51.100.2")
	replacement.Close()
	assertOnlineMapValue(t, onlineMap, 0)
}

func TestPresenceTrackerUsesOneExactBatchHandoff(t *testing.T) {
	onlineMap := appstats.NewOnlineMap()
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, &presenceTestStatsManager{onlineMap: onlineMap})
	old := make([]session.PresenceLease, 3)
	oldTokens := make(map[uint64]struct{}, len(old))
	for index := range old {
		old[index] = tracker.Prepare(session.PresenceSubject{
			Email: "alice@example.com",
			IP:    netip.MustParseAddr("192.0.2.1"),
		}).Activate()
		oldTokens[old[index].(*presenceLease).token] = struct{}{}
	}

	replacements := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("198.51.100.2"),
	}).HandoffAll(old)
	if len(replacements) != len(old) {
		t.Fatalf("replacement count = %d, want %d", len(replacements), len(old))
	}
	newTokens := make(map[uint64]struct{}, len(replacements))
	for _, replacement := range replacements {
		lease := replacement.(*presenceLease)
		if lease.exactMap != onlineMap || lease.token == 0 {
			t.Fatalf("invalid exact replacement lease: %#v", lease)
		}
		if _, stale := oldTokens[lease.token]; stale {
			t.Fatalf("batch handoff reused old token %d", lease.token)
		}
		newTokens[lease.token] = struct{}{}
	}
	if len(newTokens) != len(replacements) {
		t.Fatalf("batch handoff returned duplicate tokens: %v", newTokens)
	}
	assertOnlineMapValue(t, onlineMap, 1, "198.51.100.2")
	for _, lease := range old {
		lease.Close()
	}
	assertOnlineMapValue(t, onlineMap, 1, "198.51.100.2")
	for _, lease := range replacements {
		lease.Close()
	}
	assertOnlineMapValue(t, onlineMap, 0)
}

func TestPresenceTrackerDifferentInstanceSameGenerationFallsBack(t *testing.T) {
	newMap := appstats.NewOnlineMap()
	oldMap := newRecordingExactOnlineMap()
	oldMap.generation = newMap.OnlineMapGeneration()
	oldToken := oldMap.AcquireOnlineLease("192.0.2.1")
	old := &presenceLease{exactMap: oldMap, generation: oldMap.generation, token: oldToken}
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, &presenceTestStatsManager{onlineMap: newMap})

	replacement := tracker.Prepare(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("198.51.100.2")}).Handoff(old)
	if oldMap.replaceCalls != 0 || oldMap.releaseCalls != 1 {
		t.Fatalf("same-generation different-instance old calls: replace/release=%d/%d", oldMap.replaceCalls, oldMap.releaseCalls)
	}
	assertOnlineMapValue(t, newMap, 1, "198.51.100.2")
	replacement.Close()
	assertOnlineMapValue(t, newMap, 0)
}

func TestPresenceTrackerLegacyMapFallsBackNewBeforeOld(t *testing.T) {
	onlineMap := newRecordingLegacyOnlineMap()
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, &presenceTestStatsManager{onlineMap: onlineMap})
	old := tracker.Prepare(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.1")}).Activate()
	replacement := tracker.Prepare(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("198.51.100.2")}).Handoff(old)
	if onlineMap.refs["198.51.100.2"] != 1 || onlineMap.refs["192.0.2.1"] != 0 {
		t.Fatalf("legacy fallback refs = %v", onlineMap.refs)
	}
	want := []string{"add 192.0.2.1", "add 198.51.100.2", "remove 192.0.2.1"}
	if strings.Join(onlineMap.events, "|") != strings.Join(want, "|") {
		t.Fatalf("legacy handoff events = %v, want %v", onlineMap.events, want)
	}
	replacement.Close()
}

func TestPresenceTrackerLegacyBatchFallsBackNewBeforeOld(t *testing.T) {
	onlineMap := newRecordingLegacyOnlineMap()
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, &presenceTestStatsManager{onlineMap: onlineMap})
	old := []session.PresenceLease{
		tracker.Prepare(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.1")}).Activate(),
		tracker.Prepare(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.2")}).Activate(),
	}
	replacements := tracker.Prepare(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("198.51.100.2")}).HandoffAll(old)
	want := []string{
		"add 192.0.2.1", "add 192.0.2.2",
		"add 198.51.100.2", "add 198.51.100.2",
		"remove 192.0.2.1", "remove 192.0.2.2",
	}
	if strings.Join(onlineMap.events, "|") != strings.Join(want, "|") {
		t.Fatalf("legacy batch handoff events = %v, want %v", onlineMap.events, want)
	}
	for _, replacement := range replacements {
		replacement.Close()
	}
}

func TestPresenceTrackerDifferentGenerationFallsBackNewBeforeOld(t *testing.T) {
	newMap := appstats.NewOnlineMap()
	oldMap := newRecordingExactOnlineMap()
	oldMap.generation = newMap.OnlineMapGeneration() + 1
	oldToken := oldMap.AcquireOnlineLease("192.0.2.1")
	old := &presenceLease{exactMap: oldMap, generation: oldMap.generation, token: oldToken}
	tracker := newPresenceTracker(&presenceTestPolicy{online: true}, &presenceTestStatsManager{onlineMap: newMap})

	replacement := tracker.Prepare(session.PresenceSubject{
		Email: "alice@example.com",
		IP:    netip.MustParseAddr("198.51.100.2"),
	}).Handoff(old)
	if oldMap.replaceCalls != 0 || oldMap.releaseCalls != 1 {
		t.Fatalf("cross-generation old calls: replace/release=%d/%d", oldMap.replaceCalls, oldMap.releaseCalls)
	}
	assertOnlineMapValue(t, newMap, 1, "198.51.100.2")
	replacement.Close()
	assertOnlineMapValue(t, newMap, 0)
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

func TestPresenceTrackerRateLimitsSanitizedCrossGenerationWarning(t *testing.T) {
	oldMap := newRecordingExactOnlineMap()
	newMap := newRecordingExactOnlineMap()
	newMap.generation = 2
	policyManager := &presenceTestPolicy{online: true}
	oldTracker := newPresenceTracker(policyManager, &presenceTestStatsManager{onlineMap: oldMap})
	newTracker := newPresenceTracker(policyManager, &presenceTestStatsManager{onlineMap: newMap})
	now := time.Unix(100, 0)
	newTracker.warningNow = func() time.Time { return now }
	var warnings []string
	newTracker.warningSink = func(message string) { warnings = append(warnings, message) }

	handoff := func() {
		old := oldTracker.Prepare(session.PresenceSubject{
			Email: "alice@example.com",
			IP:    netip.MustParseAddr("192.0.2.1"),
		}).Activate()
		newTracker.Prepare(session.PresenceSubject{
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
	assertOnlineMapValue(t, onlineMap, count, wantIPs...)
}

func assertOnlineMapValue(t *testing.T, onlineMap featurestats.OnlineMap, count int, wantIPs ...string) {
	t.Helper()
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
