package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type principalTestAccount struct {
	message proto.Message
}

func (a principalTestAccount) Equals(other protocol.Account) bool {
	b, ok := other.(principalTestAccount)
	return ok && proto.Equal(a.message, b.message)
}

func (a principalTestAccount) ToProto() proto.Message { return a.message }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestCanonicalPresenceIP(t *testing.T) {
	tests := []struct {
		name string
		peer net.Addr
		want string
		ok   bool
	}{
		{name: "IPv4 TCP", peer: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, want: "192.0.2.1", ok: true},
		{name: "mapped IPv4", peer: &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 443}, want: "192.0.2.1", ok: true},
		{name: "IPv6 zone and port", peer: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443, Zone: "en0"}, want: "2001:db8::1", ok: true},
		{name: "UDP", peer: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 53}, want: "198.51.100.7", ok: true},
		{name: "IP", peer: &net.IPAddr{IP: net.ParseIP("203.0.113.9"), Zone: "en0"}, want: "203.0.113.9", ok: true},
		{name: "nil", peer: nil},
		{name: "unspecified IPv4", peer: &net.TCPAddr{IP: net.IPv4zero, Port: 1}},
		{name: "unspecified IPv6", peer: &net.TCPAddr{IP: net.IPv6unspecified, Port: 1}},
		{name: "loopback IPv4", peer: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}},
		{name: "mapped loopback", peer: &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 1}},
		{name: "loopback IPv6", peer: &net.TCPAddr{IP: net.IPv6loopback, Port: 1}},
		{name: "Unix", peer: &net.UnixAddr{Name: "/tmp/xray.sock", Net: "unix"}},
		{name: "domain", peer: domainTestAddr("client.example")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := canonicalPresenceIP(test.peer)
			if ok != test.ok {
				t.Fatalf("canonicalPresenceIP() ok = %v, want %v (address %v)", ok, test.ok, got)
			}
			if ok && got.String() != test.want {
				t.Fatalf("canonicalPresenceIP() = %s, want %s", got, test.want)
			}
		})
	}
}

type domainTestAddr string

func (domainTestAddr) Network() string  { return "tcp" }
func (a domainTestAddr) String() string { return string(a) }

func TestPresencePrincipalGoldenAndFraming(t *testing.T) {
	provider := &defaultPresenceProvider{keyValid: true, marshal: proto.MarshalOptions{Deterministic: true}.Marshal}
	for index := range provider.key {
		provider.key[index] = byte(index)
	}
	user := &protocol.MemoryUser{Account: principalTestAccount{message: wrapperspb.String("account-a")}}

	principal, reusable := provider.principalKey(user, "inbound-a", "vless")
	if !reusable {
		t.Fatal("deterministic account principal is not reusable")
	}
	const want = "29022d2405b680109aa6540fc382cf1b766c6e2492645a9ff6efdaf4fa604fce"
	if got := stringHex(principal[:]); got != want {
		t.Fatalf("principal = %s, want %s", got, want)
	}

	repeat, repeatReusable := provider.principalKey(user, "inbound-a", "vless")
	if !repeatReusable || repeat != principal {
		t.Fatalf("principal is not deterministic: %x != %x", repeat, principal)
	}
	framedLeft, _ := provider.principalKey(user, "a", "bc")
	framedRight, _ := provider.principalKey(user, "ab", "c")
	if framedLeft == framedRight {
		t.Fatal("length-delimited inbound fields collided")
	}
}

func TestPresencePrincipalSeparatesAccountTypeMaterialAndInbound(t *testing.T) {
	provider := &defaultPresenceProvider{keyValid: true, marshal: proto.MarshalOptions{Deterministic: true}.Marshal}
	copy(provider.key[:], bytes.Repeat([]byte{0x42}, len(provider.key)))
	key := func(message proto.Message, tag, name string) [32]byte {
		principal, reusable := provider.principalKey(&protocol.MemoryUser{
			Account: principalTestAccount{message: message},
		}, tag, name)
		if !reusable {
			t.Fatal("principal is not reusable")
		}
		return principal
	}

	base := key(wrapperspb.String("same"), "in", "vless")
	for description, other := range map[string][32]byte{
		"account material": key(wrapperspb.String("different"), "in", "vless"),
		"account type":     key(wrapperspb.Bytes([]byte("same")), "in", "vless"),
		"inbound tag":      key(wrapperspb.String("same"), "other", "vless"),
		"inbound name":     key(wrapperspb.String("same"), "in", "trojan"),
	} {
		if other == base {
			t.Fatalf("%s did not change principal", description)
		}
	}
}

func TestPresencePrincipalFallsBackToNonReusableEntropy(t *testing.T) {
	entropy := append(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)...)
	provider := &defaultPresenceProvider{entropy: bytes.NewReader(entropy)}
	user := &protocol.MemoryUser{Account: principalTestAccount{message: wrapperspb.String("account")}}

	first, reusable := provider.principalKey(user, "in", "vless")
	if reusable || first == ([32]byte{}) {
		t.Fatalf("invalid process key fallback = %x, reusable=%v", first, reusable)
	}
	provider.keyValid = true
	provider.marshal = func(proto.Message) ([]byte, error) { return nil, errors.New("marshal failed") }
	second, reusable := provider.principalKey(user, "in", "vless")
	if reusable || second == ([32]byte{}) || second == first {
		t.Fatalf("marshal fallback = %x, reusable=%v", second, reusable)
	}

	provider.entropy = failingReader{}
	failed, reusable := provider.principalKey(user, "in", "vless")
	if reusable || failed != ([32]byte{}) {
		t.Fatalf("failed entropy fallback = %x, reusable=%v", failed, reusable)
	}
}

type providerTestTracker struct{}

func (providerTestTracker) Prepare(session.PresenceSubject) session.PresenceReservation {
	return noopDispatcherPresence
}

func TestPresenceProviderSnapshotsAuthenticatedPhysicalPeer(t *testing.T) {
	provider := &defaultPresenceProvider{
		tracker:  providerTestTracker{},
		keyValid: true,
		marshal:  proto.MarshalOptions{Deterministic: true}.Marshal,
	}
	copy(provider.key[:], bytes.Repeat([]byte{0x42}, len(provider.key)))
	user := &protocol.MemoryUser{
		Account: principalTestAccount{message: wrapperspb.String("account")},
		Email:   "alice@example.com",
		Level:   7,
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source:       corenet.TCPDestination(corenet.ParseAddress("198.51.100.99"), 12345),
		PhysicalPeer: netip.MustParseAddr("192.0.2.9"),
		Tag:          "inbound-a",
		Name:         "vless",
		User:         user,
	})

	subject := provider.SnapshotPresence(ctx).Subject()
	if subject.Email != user.Email || subject.Level != user.Level || subject.IP.String() != "192.0.2.9" || !subject.Reusable {
		t.Fatalf("snapshot subject = %+v", subject)
	}
	movedCtx := session.ContextWithInbound(context.Background(), &session.Inbound{
		PhysicalPeer: netip.MustParseAddr("203.0.113.7"),
		Tag:          "inbound-a",
		Name:         "vless",
		User:         user,
	})
	moved := provider.SnapshotPresence(movedCtx).Subject()
	if moved.PrincipalKey != subject.PrincipalKey || moved.IP == subject.IP {
		t.Fatalf("moved snapshot = %+v, original = %+v", moved, subject)
	}
}

func TestPresenceProviderNeverFallsBackToEffectiveSource(t *testing.T) {
	provider := &defaultPresenceProvider{
		tracker:  providerTestTracker{},
		keyValid: true,
		marshal:  proto.MarshalOptions{Deterministic: true}.Marshal,
	}
	user := &protocol.MemoryUser{
		Account: principalTestAccount{message: wrapperspb.String("account")},
		Email:   "alice@example.com",
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: corenet.TCPDestination(corenet.ParseAddress("198.51.100.99"), 12345),
		Tag:    "inbound-a",
		Name:   "vless",
		User:   user,
	})
	if got := provider.SnapshotPresence(ctx).Subject(); got != (session.PresenceSubject{}) {
		t.Fatalf("effective source became presence subject: %+v", got)
	}
}

func TestDefaultDispatcherExposesPresenceProvider(t *testing.T) {
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(
		&Config{}, nil, nil,
		&presenceTestPolicy{online: true},
		&presenceTestStatsManager{},
	); err != nil {
		t.Fatal(err)
	}
	source, ok := any(dispatcher).(session.PresenceProviderSource)
	if !ok || source.PresenceProvider() == nil {
		t.Fatal("default dispatcher does not expose its presence provider")
	}
}

func stringHex(value []byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, b := range value {
		encoded[index*2] = digits[b>>4]
		encoded[index*2+1] = digits[b&0xf]
	}
	return string(encoded)
}
