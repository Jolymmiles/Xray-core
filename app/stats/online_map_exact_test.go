package stats

import (
	"context"
	"maps"
	"math"
	"testing"
)

func TestOnlineMapGenerationIdentifiesInstance(t *testing.T) {
	first := NewOnlineMap().OnlineMapGeneration()
	second := NewOnlineMap().OnlineMapGeneration()
	if first == 0 || second == 0 || first == second {
		t.Fatalf("online map generations = %d, %d; want distinct non-zero values", first, second)
	}
}

func TestOnlineMapGenerationExhaustionDisablesExactOwnership(t *testing.T) {
	previous := onlineMapGeneration.Swap(math.MaxUint64)
	t.Cleanup(func() { onlineMapGeneration.Store(previous) })

	om := NewOnlineMap()
	if got := om.OnlineMapGeneration(); got != 0 {
		t.Fatalf("exhausted online map generation = %d, want 0", got)
	}
	if token := om.AcquireOnlineLease("192.0.2.1"); token != 0 {
		t.Fatalf("exact acquire after generation exhaustion = %d, want 0", token)
	}
	if got := om.Count(); got != 0 {
		t.Fatalf("generation exhaustion mutated count = %d", got)
	}
}

func TestOnlineMapTokenExhaustionFailsWithoutMutation(t *testing.T) {
	om := NewOnlineMap()
	om.nextToken = math.MaxUint64
	if token := om.AcquireOnlineLease("192.0.2.1"); token != 0 {
		t.Fatalf("exhausted acquire token = %d, want 0", token)
	}
	if got := om.Count(); got != 0 || len(om.leases) != 0 {
		t.Fatalf("exhausted acquire mutated count=%d leases=%v", got, om.leases)
	}

	om.nextToken = math.MaxUint64 - 1
	old := om.AcquireOnlineLease("192.0.2.1")
	if old != math.MaxUint64 {
		t.Fatalf("last available token = %d, want %d", old, uint64(math.MaxUint64))
	}
	if replacements, ok := om.ReplaceOnlineLeases([]uint64{old}, "198.51.100.2", 1); ok || replacements != nil {
		t.Fatalf("replacement after exhaustion = %v, %v; want nil, false", replacements, ok)
	}
	if got := onlineMapIPs(om); !maps.Equal(got, map[string]bool{"192.0.2.1": true}) {
		t.Fatalf("exhausted replacement mutated map: %v", got)
	}
}

func TestOnlineMapLegacyRemovalCannotConsumeExactLease(t *testing.T) {
	om := NewOnlineMap()
	token := om.AcquireOnlineLease("192.0.2.1")
	om.RemoveIP("192.0.2.1")
	if got := om.Count(); got != 1 {
		t.Fatalf("legacy removal consumed exact lease: count = %d", got)
	}
	om.AddIP("192.0.2.1")
	om.ReleaseOnlineLease(token)
	if got := om.Count(); got != 1 {
		t.Fatalf("exact release consumed legacy reference: count = %d", got)
	}
	om.RemoveIP("192.0.2.1")
	if got := om.Count(); got != 0 {
		t.Fatalf("count after releasing both reference kinds = %d, want 0", got)
	}
}

func TestOnlineMapExactLeaseReleaseUsesToken(t *testing.T) {
	om := NewOnlineMap()
	if om.OnlineMapGeneration() == 0 {
		t.Fatal("online map generation is zero")
	}

	first := om.AcquireOnlineLease("192.0.2.1")
	second := om.AcquireOnlineLease("192.0.2.1")
	if first == 0 || second == 0 || first == second {
		t.Fatalf("exact tokens = %d, %d; want distinct non-zero tokens", first, second)
	}
	if got := om.Count(); got != 1 {
		t.Fatalf("unique IP count = %d, want 1", got)
	}

	om.ReleaseOnlineLease(first)
	om.ReleaseOnlineLease(first)
	if got := om.Count(); got != 1 {
		t.Fatalf("duplicate exact release removed another owner: count = %d", got)
	}
	om.ReleaseOnlineLease(second)
	if got := om.Count(); got != 0 {
		t.Fatalf("count after final exact release = %d, want 0", got)
	}
}

func TestOnlineMapReplaceLeasePreservesUnrelatedOldIPOwner(t *testing.T) {
	om := NewOnlineMap()
	unrelated := om.AcquireOnlineLease("192.0.2.1")
	old := om.AcquireOnlineLease("192.0.2.1")

	replacements, ok := om.ReplaceOnlineLeases([]uint64{old}, "198.51.100.2", 1)
	if !ok || len(replacements) != 1 || replacements[0] == 0 || replacements[0] == old {
		t.Fatalf("replacement = %v, ok = %v; want one fresh token", replacements, ok)
	}
	if got := om.Count(); got != 2 {
		t.Fatalf("unique IP count after handoff = %d, want 2", got)
	}

	om.ReleaseOnlineLease(old)
	if got := om.Count(); got != 2 {
		t.Fatalf("stale old release changed replacement state: count = %d", got)
	}
	om.ReleaseOnlineLease(unrelated)
	if got := om.Count(); got != 1 {
		t.Fatalf("unrelated old-IP release count = %d, want 1", got)
	}
	om.ReleaseOnlineLease(replacements[0])
	if got := om.Count(); got != 0 {
		t.Fatalf("final count = %d, want 0", got)
	}
}

func TestOnlineMapReplaceLeaseRejectsDuplicateTokenWithoutMutation(t *testing.T) {
	om := NewOnlineMap()
	token := om.AcquireOnlineLease("192.0.2.1")

	replacements, ok := om.ReplaceOnlineLeases([]uint64{token, token}, "198.51.100.2", 2)
	if ok || replacements != nil {
		t.Fatalf("duplicate replacement = %v, ok = %v; want validation failure", replacements, ok)
	}
	if got := om.Count(); got != 1 {
		t.Fatalf("failed validation mutated unique count = %d, want 1", got)
	}
	om.ReleaseOnlineLease(token)
	if got := om.Count(); got != 0 {
		t.Fatalf("failed validation consumed original token: count = %d", got)
	}
}

func TestOnlineMapReplaceLeaseAtSameIPCreatesFreshToken(t *testing.T) {
	om := NewOnlineMap()
	old := om.AcquireOnlineLease("192.0.2.1")

	replacements, ok := om.ReplaceOnlineLeases([]uint64{old}, "192.0.2.1", 1)
	if !ok || len(replacements) != 1 || replacements[0] == 0 || replacements[0] == old {
		t.Fatalf("same-IP replacement = %v, ok = %v; want one fresh token", replacements, ok)
	}
	if got := om.Count(); got != 1 {
		t.Fatalf("same-IP replacement count = %d, want 1", got)
	}

	om.ReleaseOnlineLease(old)
	if got := om.Count(); got != 1 {
		t.Fatalf("stale same-IP release changed replacement: count = %d", got)
	}
	om.ReleaseOnlineLease(replacements[0])
	if got := om.Count(); got != 0 {
		t.Fatalf("final count = %d, want 0", got)
	}
}

func TestOnlineMapReplaceBatchMovesCompleteOwnerSet(t *testing.T) {
	om := NewOnlineMap()
	old := []uint64{
		om.AcquireOnlineLease("192.0.2.1"),
		om.AcquireOnlineLease("192.0.2.1"),
		om.AcquireOnlineLease("192.0.2.1"),
	}
	unrelated := om.AcquireOnlineLease("203.0.113.3")

	replacements, ok := om.ReplaceOnlineLeases(old, "198.51.100.2", len(old))
	if !ok || len(replacements) != len(old) {
		t.Fatalf("batch replacement = %v, ok = %v", replacements, ok)
	}
	if got := onlineMapIPs(om); !maps.Equal(got, map[string]bool{"198.51.100.2": true, "203.0.113.3": true}) {
		t.Fatalf("IPs after batch replacement = %v", got)
	}

	for _, token := range old {
		om.ReleaseOnlineLease(token)
	}
	if got := om.Count(); got != 2 {
		t.Fatalf("stale batch releases changed state: count = %d, want 2", got)
	}
	for _, token := range replacements {
		om.ReleaseOnlineLease(token)
	}
	om.ReleaseOnlineLease(unrelated)
	if got := om.Count(); got != 0 {
		t.Fatalf("final count = %d, want 0", got)
	}
}

func TestOnlineMapUnregisterKeepsLeaseGenerationsIsolated(t *testing.T) {
	manager, err := NewManager(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	const name = "user>>>alice@example.com>>>online"

	registered, err := manager.GetOrRegisterOnlineMap(name)
	if err != nil {
		t.Fatal(err)
	}
	oldMap := registered.(*OnlineMap)
	oldToken := oldMap.AcquireOnlineLease("192.0.2.1")
	if err := manager.UnregisterOnlineMap(name); err != nil {
		t.Fatal(err)
	}
	registered, err = manager.GetOrRegisterOnlineMap(name)
	if err != nil {
		t.Fatal(err)
	}
	newMap := registered.(*OnlineMap)
	newToken := newMap.AcquireOnlineLease("198.51.100.2")

	if oldMap.OnlineMapGeneration() == newMap.OnlineMapGeneration() {
		t.Fatal("re-registered map reused generation")
	}
	oldMap.ReleaseOnlineLease(oldToken)
	if got := onlineMapIPs(newMap); !maps.Equal(got, map[string]bool{"198.51.100.2": true}) {
		t.Fatalf("old lease release mutated new generation: %v", got)
	}
	newMap.ReleaseOnlineLease(newToken)
}

func onlineMapIPs(om *OnlineMap) map[string]bool {
	ips := make(map[string]bool)
	om.ForEach(func(ip string, _ int64) bool {
		ips[ip] = true
		return true
	})
	return ips
}
