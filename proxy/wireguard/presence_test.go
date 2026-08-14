package wireguard

import (
	"errors"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/session"
	presencefixture "github.com/xtls/xray-core/testing/presence"
	"golang.zx2c4.com/wireguard/tun"
)

func TestAuthenticatedPeerStateUsesOuterEndpoint(t *testing.T) {
	first := [32]byte{1}
	second := [32]byte{2}
	state := wireGuardState(first, "198.51.100.10:51820", "10.0.0.0/24") +
		wireGuardState(second, "[2001:db8::20]:51820", "10.0.0.8/32")

	pub, endpoint, ok := authenticatedPeerState(state, netip.MustParseAddr("10.0.0.8"))
	if !ok || pub != second || endpoint != netip.MustParseAddrPort("[2001:db8::20]:51820") {
		t.Fatalf("state = %x %v %v", pub, endpoint, ok)
	}
	if endpoint.Addr() == netip.MustParseAddr("10.0.0.8") {
		t.Fatal("inner tunnel address was used as presence endpoint")
	}

	if _, _, ok := authenticatedPeerState(wireGuardState(first, "", "10.0.0.0/24"), netip.MustParseAddr("10.0.0.1")); ok {
		t.Fatal("peer without a server-observed endpoint was accepted")
	}
}

func TestAuthenticatedTunObservesBeforeDeliveringData(t *testing.T) {
	underlying := &wireGuardTestTun{}
	var events []string
	underlying.write = func() { events = append(events, "write") }
	observed := &authenticatedTun{
		Device: underlying,
		observe: func(bufs [][]byte, offset int) {
			events = append(events, "observe")
			if got := bufs[0][offset:]; !slices.Equal(got, []byte{4, 5, 6}) {
				t.Fatalf("observed packet = %v", got)
			}
		},
	}
	if n, err := observed.Write([][]byte{{1, 2, 3, 4, 5, 6}}, 3); err != nil || n != 1 {
		t.Fatalf("write = %d, %v", n, err)
	}
	if !slices.Equal(events, []string{"observe", "write"}) {
		t.Fatalf("events = %v", events)
	}
}

func TestWireGuardPacketSource(t *testing.T) {
	ipv4 := make([]byte, 20)
	ipv4[0] = 4 << 4
	copy(ipv4[12:16], netip.MustParseAddr("10.0.0.1").AsSlice())
	ipv6 := make([]byte, 40)
	ipv6[0] = 6 << 4
	copy(ipv6[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	for _, test := range []struct {
		packet []byte
		want   netip.Addr
	}{
		{packet: ipv4, want: netip.MustParseAddr("10.0.0.1")},
		{packet: ipv6, want: netip.MustParseAddr("2001:db8::1")},
	} {
		got, ok := wireGuardPacketSource(test.packet)
		if !ok || got != test.want {
			t.Fatalf("source = %v, %v; want %v", got, ok, test.want)
		}
	}
	if _, ok := wireGuardPacketSource([]byte{0}); ok {
		t.Fatal("invalid packet returned a source")
	}
}

func TestWireGuardPresenceOwnsFlowsNotBindings(t *testing.T) {
	tracker := newWireGuardTestTracker()
	presence := newWireGuardPresence()
	pub := [32]byte{1}
	ip := netip.MustParseAddr("192.0.2.10")
	presence.Observe(pub, 1, ip, wireGuardTestScope(tracker, ip))
	tracker.assert(t)

	flow := presence.Open(pub)
	tracker.assert(t, "192.0.2.10")
	flow.Close()
	tracker.assert(t)

	if flow := presence.Open([32]byte{9}); flow != nil {
		t.Fatal("missing endpoint binding created a flow owner")
	}
}

func TestWireGuardStatsServiceTracksFlowAndRoam(t *testing.T) {
	fixture := presencefixture.New(t)
	presence := newWireGuardPresence()
	pub := [32]byte{8}
	presence.Observe(pub, 1, netip.MustParseAddr("192.0.2.10"), fixture.Scope(t, "wireguard-roam@example.com", "192.0.2.10"))
	fixture.AssertIPs(t, "wireguard-roam@example.com")
	first := presence.Open(pub)
	second := presence.Open(pub)
	fixture.AssertIPs(t, "wireguard-roam@example.com", "192.0.2.10")

	presence.Observe(pub, 2, netip.MustParseAddr("198.51.100.20"), fixture.Scope(t, "wireguard-roam@example.com", "198.51.100.20"))
	fixture.AssertIPs(t, "wireguard-roam@example.com", "198.51.100.20")
	presence.Observe(pub, 1, netip.MustParseAddr("192.0.2.10"), fixture.Scope(t, "wireguard-roam@example.com", "192.0.2.10"))
	fixture.AssertIPs(t, "wireguard-roam@example.com", "198.51.100.20")

	first.Close()
	fixture.AssertIPs(t, "wireguard-roam@example.com", "198.51.100.20")
	second.Close()
	fixture.AssertIPs(t, "wireguard-roam@example.com")
}

func TestWireGuardPresenceRoamsAllFlowsOnce(t *testing.T) {
	tracker := newWireGuardTestTracker()
	presence := newWireGuardPresence()
	pub := [32]byte{1}
	firstIP := netip.MustParseAddr("192.0.2.10")
	secondIP := netip.MustParseAddr("198.51.100.20")
	presence.Observe(pub, 1, firstIP, wireGuardTestScope(tracker, firstIP))
	first := presence.Open(pub)
	second := presence.Open(pub)
	tracker.assert(t, "192.0.2.10", "192.0.2.10")

	presence.Observe(pub, 2, secondIP, wireGuardTestScope(tracker, secondIP))
	tracker.assert(t, "198.51.100.20", "198.51.100.20")
	if tracker.batchCalls != 1 {
		t.Fatalf("batch handoffs = %d, want 1", tracker.batchCalls)
	}

	presence.Observe(pub, 3, secondIP, wireGuardTestScope(tracker, secondIP))
	if tracker.batchCalls != 1 {
		t.Fatalf("same-IP handoffs = %d, want 1", tracker.batchCalls)
	}
	presence.Observe(pub, 1, firstIP, wireGuardTestScope(tracker, firstIP))
	tracker.assert(t, "198.51.100.20", "198.51.100.20")

	first.Close()
	tracker.assert(t, "198.51.100.20")
	second.Close()
	tracker.assert(t)
}

func TestWireGuardPresenceRemovalAndCloseDrainFlows(t *testing.T) {
	tracker := newWireGuardTestTracker()
	presence := newWireGuardPresence()
	firstPub := [32]byte{1}
	secondPub := [32]byte{2}
	firstIP := netip.MustParseAddr("192.0.2.10")
	secondIP := netip.MustParseAddr("198.51.100.20")
	presence.Observe(firstPub, 1, firstIP, wireGuardTestScope(tracker, firstIP))
	presence.Observe(secondPub, 1, secondIP, wireGuardTestScope(tracker, secondIP))
	first := presence.Open(firstPub)
	second := presence.Open(secondPub)
	tracker.assert(t, "192.0.2.10", "198.51.100.20")

	presence.Remove(firstPub)
	tracker.assert(t, "198.51.100.20")
	if flow := presence.Open(firstPub); flow != nil {
		t.Fatal("removed peer admitted a flow")
	}
	presence.Close()
	tracker.assert(t)
	if flow := presence.Open(secondPub); flow != nil {
		t.Fatal("closed server admitted a flow")
	}

	first.Close()
	second.Close()
}

func TestWireGuardPresenceConcurrentAdmissionAndRoam(t *testing.T) {
	tracker := newWireGuardTestTracker()
	presence := newWireGuardPresence()
	pub := [32]byte{1}
	firstIP := netip.MustParseAddr("192.0.2.10")
	secondIP := netip.MustParseAddr("198.51.100.20")
	presence.Observe(pub, 1, firstIP, wireGuardTestScope(tracker, firstIP))

	start := make(chan struct{})
	flows := make([]*wireGuardFlow, 64)
	var wait sync.WaitGroup
	for index := range flows {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			flows[index] = presence.Open(pub)
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		presence.Observe(pub, 2, secondIP, wireGuardTestScope(tracker, secondIP))
	}()
	close(start)
	wait.Wait()

	for _, flow := range flows {
		if flow == nil {
			t.Fatal("concurrent flow admission failed")
		}
		flow.Close()
	}
	tracker.assert(t)
}

func TestWireGuardPresenceThousandHandoffsEndAtZero(t *testing.T) {
	tracker := newWireGuardTestTracker()
	presence := newWireGuardPresence()
	pub := [32]byte{1}
	firstIP := netip.MustParseAddr("192.0.2.10")
	presence.Observe(pub, 1, firstIP, wireGuardTestScope(tracker, firstIP))
	flow := presence.Open(pub)
	for observation := uint64(2); observation <= 1001; observation++ {
		ip := netip.AddrFrom4([4]byte{198, 51, byte(observation >> 8), byte(observation)})
		presence.Observe(pub, observation, ip, wireGuardTestScope(tracker, ip))
	}
	if tracker.batchCalls != 1000 {
		t.Fatalf("batch handoffs = %d, want 1000", tracker.batchCalls)
	}
	flow.Close()
	tracker.assert(t)
}

func wireGuardState(pub [32]byte, endpoint string, allowed string) string {
	state := "public_key=" + encodeWireGuardKey(pub) + "\n"
	if endpoint != "" {
		state += "endpoint=" + endpoint + "\n"
	}
	return state + "allowed_ip=" + allowed + "\n"
}

type wireGuardTestTracker struct {
	mu         sync.Mutex
	next       uint64
	live       map[uint64]string
	batchCalls int
}

func newWireGuardTestTracker() *wireGuardTestTracker {
	return &wireGuardTestTracker{live: make(map[uint64]string)}
}

func wireGuardTestScope(tracker *wireGuardTestTracker, ip netip.Addr) session.PresenceScope {
	return session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: ip}, tracker)
}

func (t *wireGuardTestTracker) Prepare(subject session.PresenceSubject) session.PresenceReservation {
	return &wireGuardTestReservation{tracker: t, ip: subject.IP.String()}
}

func (t *wireGuardTestTracker) assert(testingT *testing.T, want ...string) {
	testingT.Helper()
	t.mu.Lock()
	got := make([]string, 0, len(t.live))
	for _, ip := range t.live {
		got = append(got, ip)
	}
	t.mu.Unlock()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		testingT.Fatalf("live IPs = %v, want %v", got, want)
	}
}

type wireGuardTestReservation struct {
	tracker *wireGuardTestTracker
	ip      string
}

func (r *wireGuardTestReservation) Activate() session.PresenceLease {
	return r.activate()
}

func (r *wireGuardTestReservation) Handoff(old session.PresenceLease) session.PresenceLease {
	replacement := r.activate()
	old.Close()
	return replacement
}

func (r *wireGuardTestReservation) HandoffAll(old []session.PresenceLease) []session.PresenceLease {
	r.tracker.mu.Lock()
	r.tracker.batchCalls++
	r.tracker.mu.Unlock()
	replacements := make([]session.PresenceLease, len(old))
	for index := range old {
		replacements[index] = r.activate()
	}
	for _, lease := range old {
		lease.Close()
	}
	return replacements
}

func (*wireGuardTestReservation) Abort() {}

func (r *wireGuardTestReservation) activate() session.PresenceLease {
	r.tracker.mu.Lock()
	r.tracker.next++
	token := r.tracker.next
	r.tracker.live[token] = r.ip
	r.tracker.mu.Unlock()
	return &wireGuardTestLease{tracker: r.tracker, token: token}
}

type wireGuardTestLease struct {
	tracker *wireGuardTestTracker
	token   uint64
	once    sync.Once
}

func (l *wireGuardTestLease) Close() {
	l.once.Do(func() {
		l.tracker.mu.Lock()
		delete(l.tracker.live, l.token)
		l.tracker.mu.Unlock()
	})
}

type wireGuardTestTun struct {
	write func()
}

func (*wireGuardTestTun) File() *os.File { return nil }

func (*wireGuardTestTun) Read([][]byte, []int, int) (int, error) { return 0, errors.New("unused") }

func (t *wireGuardTestTun) Write(bufs [][]byte, _ int) (int, error) {
	t.write()
	return len(bufs), nil
}

func (*wireGuardTestTun) MTU() (int, error) { return 1500, nil }

func (*wireGuardTestTun) Name() (string, error) { return "test", nil }

func (*wireGuardTestTun) Events() <-chan tun.Event { return nil }

func (*wireGuardTestTun) Close() error { return nil }

func (*wireGuardTestTun) BatchSize() int { return 1 }
