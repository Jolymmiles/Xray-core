package dispatcher

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	stdnet "net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	statscommand "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type presenceTestAccount struct {
	value string
}

type presenceTestPolicyManager struct {
	online bool
}

func (*presenceTestPolicyManager) Start() error             { return nil }
func (*presenceTestPolicyManager) Close() error             { return nil }
func (*presenceTestPolicyManager) Type() interface{}        { return policy.ManagerType() }
func (*presenceTestPolicyManager) ForSystem() policy.System { return policy.System{} }
func (m *presenceTestPolicyManager) ForLevel(uint32) policy.Session {
	return policy.Session{Stats: policy.Stats{UserOnline: m.online}}
}

func (a presenceTestAccount) Equals(other protocol.Account) bool {
	b, ok := other.(presenceTestAccount)
	return ok && a.value == b.value
}

func (a presenceTestAccount) ToProto() proto.Message {
	return wrapperspb.String(a.value)
}

func TestCanonicalPresenceIP(t *testing.T) {
	tests := []struct {
		name string
		dest net.Destination
		want string
		ok   bool
	}{
		{name: "ipv4", dest: net.TCPDestination(net.IPAddress(stdnet.ParseIP("192.0.2.1")), 443), want: "192.0.2.1", ok: true},
		{name: "mapped ipv4", dest: net.TCPDestination(net.IPAddress([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}), 443), want: "192.0.2.1", ok: true},
		{name: "ipv6", dest: net.TCPDestination(net.IPAddress(stdnet.ParseIP("2001:0db8:0:0:0:0:0:1")), 443), want: "[2001:db8::1]", ok: true},
		{name: "ipv4 loopback", dest: net.TCPDestination(net.LocalHostIP, 1)},
		{name: "ipv6 loopback", dest: net.TCPDestination(net.LocalHostIPv6, 1)},
		{name: "ipv4 unspecified", dest: net.TCPDestination(net.AnyIP, 1)},
		{name: "ipv6 unspecified", dest: net.TCPDestination(net.AnyIPv6, 1)},
		{name: "domain", dest: net.TCPDestination(net.DomainAddress("example.com"), 443)},
		{name: "unix", dest: net.UnixDestination(net.DomainAddress("/tmp/xray.sock"))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := canonicalPresenceIP(test.dest)
			if ok != test.ok {
				t.Fatalf("canonicalPresenceIP() ok = %v; want %v", ok, test.ok)
			}
			if !ok {
				return
			}
			if got != netip.MustParseAddr(strings.Trim(test.want, "[]")) {
				t.Fatalf("canonicalPresenceIP() = %s; want %s", got, test.want)
			}
			if formatted := formatPresenceIP(got); formatted != test.want {
				t.Fatalf("formatPresenceIP() = %q; want %q", formatted, test.want)
			}
		})
	}
}

func TestPrincipalKeyUsesCanonicalAuthenticatedIdentity(t *testing.T) {
	key := [32]byte{1, 2, 3, 4}
	provider := &defaultPresenceProvider{
		key:      key,
		keyValid: true,
		marshal:  proto.MarshalOptions{Deterministic: true}.Marshal,
		entropy:  bytes.NewReader(bytes.Repeat([]byte{9}, 64)),
	}
	user := &protocol.MemoryUser{Account: presenceTestAccount{value: "account-id"}, Email: "first@example.com", Level: 7}

	got, reusable := provider.principalKey(user, "inbound-a", "vless")
	if !reusable {
		t.Fatal("authenticated serializable account must be reusable")
	}

	message := user.Account.ToProto()
	accountBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	wantMAC := hmac.New(sha256.New, key[:])
	_, _ = wantMAC.Write([]byte(principalDomainSeparator))
	for _, field := range [][]byte{
		[]byte(message.ProtoReflect().Descriptor().FullName()),
		accountBytes,
		[]byte("inbound-a"),
		[]byte("vless"),
	} {
		var length [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(length[:], uint64(len(field)))
		_, _ = wantMAC.Write(length[:n])
		_, _ = wantMAC.Write(field)
	}
	var want [32]byte
	copy(want[:], wantMAC.Sum(nil))
	if got != want {
		t.Fatalf("principalKey() = %x; want %x", got, want)
	}

	user.Email = "renamed@example.com"
	same, reusable := provider.principalKey(user, "inbound-a", "vless")
	if !reusable || same != got {
		t.Fatal("email must not affect principal key")
	}
	different, reusable := provider.principalKey(user, "inbound-b", "vless")
	if !reusable || different == got {
		t.Fatal("inbound scope must affect principal key")
	}
}

func TestPresenceProviderUsesCarrierSourceAndFailsClosed(t *testing.T) {
	key := [32]byte{1}
	provider := &defaultPresenceProvider{
		key:      key,
		keyValid: true,
		marshal: func(proto.Message) ([]byte, error) {
			return nil, errors.New("serialization failed")
		},
		entropy: bytes.NewReader(bytes.Repeat([]byte{7}, 32)),
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source:        net.TCPDestination(net.ParseAddress("203.0.113.55"), 1),
		CarrierSource: net.TCPDestination(net.ParseAddress("192.0.2.44"), 2),
		Tag:           "inbound-a",
		Name:          "vless",
		User:          &protocol.MemoryUser{Account: presenceTestAccount{value: "account-id"}, Email: "user@example.com", Level: 7},
	})

	scope := provider.SnapshotPresence(ctx)
	if got := formatPresenceIP(scope.Subject.IP); got != "192.0.2.44" {
		t.Fatalf("presence IP = %s; want raw carrier 192.0.2.44", got)
	}
	if scope.Subject.Reusable {
		t.Fatal("serialization failure must disable cross-carrier reuse")
	}
	if scope.Subject.PrincipalKey != [32]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7} {
		t.Fatalf("carrier-local nonce = %x; want injected entropy", scope.Subject.PrincipalKey)
	}

	provider.entropy = bytes.NewReader(nil)
	scope = provider.SnapshotPresence(ctx)
	if scope.Subject.Reusable || scope.Subject.PrincipalKey != ([32]byte{}) {
		t.Fatal("entropy failure must leave scope explicitly non-reusable without a key")
	}
}

func TestPresenceLeaseLifecycleAndAtomicHandoff(t *testing.T) {
	statsManager, err := appstats.NewManager(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	policyManager := &presenceTestPolicyManager{online: true}
	tracker := &onlinePresenceTracker{policy: policyManager, stats: statsManager}
	statsServer := statscommand.NewStatsServer(statsManager)
	statsName := "user>>>user@example.com>>>online"
	subject := session.PresenceSubject{Email: "user@example.com", Level: 7, IP: netip.MustParseAddr("192.0.2.1")}

	first := tracker.Prepare(subject).Activate()
	second := tracker.Prepare(subject).Activate()
	onlineMap := statsManager.GetOnlineMap("user>>>user@example.com>>>online")
	if onlineMap == nil || onlineMap.Count() != 1 {
		t.Fatalf("unique IP count = %v; want 1", onlineMap)
	}
	assertDispatcherRPCOnline(t, statsServer, statsName, 1)
	first.Close()
	if onlineMap.Count() != 1 {
		t.Fatal("closing one of two leases removed the shared IP")
	}

	newSubject := subject
	newSubject.IP = netip.MustParseAddr("2001:db8::1")
	third := tracker.Prepare(newSubject).Handoff(second)
	var ips []string
	onlineMap.ForEach(func(ip string, _ int64) bool {
		ips = append(ips, ip)
		return true
	})
	if len(ips) != 1 || ips[0] != "[2001:db8::1]" {
		t.Fatalf("IPs after handoff = %v; want [[2001:db8::1]]", ips)
	}
	assertDispatcherRPCOnline(t, statsServer, statsName, 1)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			third.Close()
		}()
	}
	wg.Wait()
	if onlineMap.Count() != 0 {
		t.Fatalf("count after concurrent Close = %d; want 0", onlineMap.Count())
	}
	assertDispatcherRPCOnline(t, statsServer, statsName, 0)
}

func assertDispatcherRPCOnline(t *testing.T, server statscommand.StatsServiceServer, name string, want int64) {
	t.Helper()
	response, err := server.GetStatsOnline(context.Background(), &statscommand.GetStatsRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Stat.Value; got != want {
		t.Fatalf("StatsService online value = %d; want %d", got, want)
	}
}

func TestPresenceLeasePinsOnlineMapGeneration(t *testing.T) {
	statsManager, err := appstats.NewManager(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker := &onlinePresenceTracker{policy: &presenceTestPolicyManager{online: true}, stats: statsManager}
	subject := session.PresenceSubject{Email: "user@example.com", IP: netip.MustParseAddr("192.0.2.1")}
	oldLease := tracker.Prepare(subject).Activate()
	name := "user>>>user@example.com>>>online"
	if err := statsManager.UnregisterOnlineMap(name); err != nil {
		t.Fatal(err)
	}
	newLease := tracker.Prepare(subject).Activate()
	newMap := statsManager.GetOnlineMap(name)
	oldLease.Close()
	if newMap.Count() != 1 {
		t.Fatal("old lease close modified replacement OnlineMap")
	}
	newLease.Close()
	if newMap.Count() != 0 {
		t.Fatal("replacement lease did not balance its own OnlineMap")
	}
}

func TestPresencePolicyDisabledUsesNoopLease(t *testing.T) {
	statsManager, err := appstats.NewManager(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker := &onlinePresenceTracker{policy: &presenceTestPolicyManager{}, stats: statsManager}
	lease := tracker.Prepare(session.PresenceSubject{Email: "user@example.com", IP: netip.MustParseAddr("192.0.2.1")}).Activate()
	lease.Close()
	if got := statsManager.GetOnlineMap("user>>>user@example.com>>>online"); got != nil {
		t.Fatal("disabled policy registered an OnlineMap")
	}
}

func TestStructuralMuxContextSuppressesDispatcherOwnedPresence(t *testing.T) {
	statsManager, err := appstats.NewManager(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(nil, nil, nil, &presenceTestPolicyManager{online: true}, statsManager); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		CarrierSource: net.TCPDestination(net.ParseAddress("192.0.2.1"), 1234),
		Tag:           "inbound-a",
		Name:          "vless",
		User:          &protocol.MemoryUser{Account: presenceTestAccount{value: "account-id"}, Email: "user@example.com"},
	})
	ctx = session.ContextWithPresenceMode(ctx, session.PresenceModeStructural)
	dispatcher.getLink(ctx)
	if got := statsManager.GetOnlineMap("user>>>user@example.com>>>online"); got != nil {
		t.Fatal("dispatcher acquired a context-owned lease for structural Mux")
	}
}
