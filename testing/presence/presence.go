package presence

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	statscmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/session"
	featurestats "github.com/xtls/xray-core/features/stats"
)

// Fixture exposes real exact OnlineMap ownership and StatsService over one
// in-memory stats manager for structural owner integration tests.
type Fixture struct {
	manager *appstats.Manager
	server  statscmd.StatsServiceServer
}

func (f *Fixture) Manager() featurestats.Manager { return f.manager }

func New(testingT testing.TB) *Fixture {
	testingT.Helper()
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		testingT.Fatal(err)
	}
	return &Fixture{manager: manager, server: statscmd.NewStatsServer(manager)}
}

func (f *Fixture) Scope(testingT testing.TB, email, ip string) session.PresenceScope {
	testingT.Helper()
	onlineMap, err := f.manager.GetOrRegisterOnlineMap(metric(email))
	if err != nil {
		testingT.Fatal(err)
	}
	exact, ok := onlineMap.(*appstats.OnlineMap)
	if !ok {
		testingT.Fatalf("online map = %T, want *stats.OnlineMap", onlineMap)
	}
	return session.NewPresenceScope(session.PresenceSubject{Email: email, IP: mustIP(ip)}, &exactTracker{online: exact})
}

func (f *Fixture) AssertIPCount(testingT testing.TB, email string, want int) {
	testingT.Helper()
	onlineMap := f.manager.GetOnlineMap(metric(email))
	if onlineMap == nil {
		testingT.Fatalf("online map %q not found", metric(email))
	}
	if got := onlineMap.Count(); got != want {
		testingT.Fatalf("online IP count = %d, want %d", got, want)
	}
}

func (f *Fixture) AssertIPs(testingT testing.TB, email string, want ...string) {
	testingT.Helper()
	if _, err := f.manager.GetOrRegisterOnlineMap(metric(email)); err != nil {
		testingT.Fatal(err)
	}
	response, err := f.server.GetStatsOnlineIpList(context.Background(), &statscmd.GetStatsRequest{Name: metric(email)})
	if err != nil {
		testingT.Fatal(err)
	}
	if !sameIPs(response.Ips, want) {
		testingT.Fatalf("StatsService online IPs = %v, want %v", response.Ips, want)
	}
}

func (f *Fixture) WaitIPs(testingT testing.TB, email string, want ...string) {
	testingT.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := f.manager.GetOrRegisterOnlineMap(metric(email)); err != nil {
			testingT.Fatal(err)
		}
		response, err := f.server.GetStatsOnlineIpList(context.Background(), &statscmd.GetStatsRequest{Name: metric(email)})
		if err == nil && sameIPs(response.Ips, want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	f.AssertIPs(testingT, email, want...)
}

func metric(email string) string { return "user>>>" + email + ">>>online" }

func mustIP(ip string) (address netip.Addr) {
	return netip.MustParseAddr(ip)
}

func sameIPs(got map[string]int64, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, ip := range want {
		if _, found := got[ip]; !found {
			return false
		}
	}
	return true
}

type exactTracker struct{ online *appstats.OnlineMap }

func (t *exactTracker) Prepare(subject session.PresenceSubject) session.PresenceReservation {
	return &exactReservation{online: t.online, ip: subject.IP.String()}
}

type exactReservation struct {
	online   *appstats.OnlineMap
	ip       string
	terminal atomic.Bool
}

func (r *exactReservation) Activate() session.PresenceLease {
	if !r.terminal.CompareAndSwap(false, true) {
		return noopLease{}
	}
	return r.acquire()
}

func (r *exactReservation) Handoff(old session.PresenceLease) session.PresenceLease {
	if !r.terminal.CompareAndSwap(false, true) {
		return noopLease{}
	}
	oldLease, ok := old.(*exactLease)
	if ok && oldLease.online == r.online && oldLease.closed.CompareAndSwap(false, true) {
		tokens, replaced := r.online.ReplaceOnlineLeases([]uint64{oldLease.token}, r.ip, 1)
		if replaced && len(tokens) == 1 {
			return &exactLease{online: r.online, token: tokens[0]}
		}
		r.online.ReleaseOnlineLease(oldLease.token)
	}
	lease := r.acquire()
	if !ok && old != nil {
		old.Close()
	}
	return lease
}

func (r *exactReservation) HandoffAll(old []session.PresenceLease) []session.PresenceLease {
	if !r.terminal.CompareAndSwap(false, true) {
		return make([]session.PresenceLease, len(old))
	}
	tokens := make([]uint64, len(old))
	leases := make([]*exactLease, len(old))
	for index, lease := range old {
		exact, ok := lease.(*exactLease)
		if !ok || exact.online != r.online || !exact.closed.CompareAndSwap(false, true) {
			for previous := 0; previous < index; previous++ {
				leases[previous].closed.Store(false)
			}
			return r.fallbackAll(old)
		}
		leases[index], tokens[index] = exact, exact.token
	}
	replacements, replaced := r.online.ReplaceOnlineLeases(tokens, r.ip, len(old))
	if !replaced || len(replacements) != len(old) {
		for index, lease := range leases {
			lease.closed.Store(false)
			_ = index
		}
		return r.fallbackAll(old)
	}
	result := make([]session.PresenceLease, len(replacements))
	for index, token := range replacements {
		result[index] = &exactLease{online: r.online, token: token}
	}
	return result
}

func (r *exactReservation) fallbackAll(old []session.PresenceLease) []session.PresenceLease {
	result := make([]session.PresenceLease, len(old))
	for index := range result {
		result[index] = r.acquire()
	}
	for _, lease := range old {
		if lease != nil {
			lease.Close()
		}
	}
	return result
}

func (r *exactReservation) Abort() { r.terminal.CompareAndSwap(false, true) }

func (r *exactReservation) acquire() session.PresenceLease {
	token := r.online.AcquireOnlineLease(r.ip)
	if token == 0 {
		return noopLease{}
	}
	return &exactLease{online: r.online, token: token}
}

type exactLease struct {
	online *appstats.OnlineMap
	token  uint64
	closed atomic.Bool
}

func (l *exactLease) Close() {
	if l != nil && l.closed.CompareAndSwap(false, true) {
		l.online.ReleaseOnlineLease(l.token)
	}
}

type noopLease struct{}

func (noopLease) Close() {}
