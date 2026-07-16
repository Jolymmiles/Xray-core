package dispatcher

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	featurestats "github.com/xtls/xray-core/features/stats"
	"google.golang.org/protobuf/proto"
)

const principalDomainSeparator = "xray-online-principal-v1"

type defaultPresenceProvider struct {
	tracker  session.PresenceTracker
	key      [32]byte
	keyValid bool
	marshal  func(proto.Message) ([]byte, error)
	entropy  io.Reader
}

func newDefaultPresenceProvider(tracker session.PresenceTracker) *defaultPresenceProvider {
	provider := &defaultPresenceProvider{
		tracker: tracker,
		marshal: proto.MarshalOptions{Deterministic: true}.Marshal,
		entropy: cryptorand.Reader,
	}
	if _, err := io.ReadFull(cryptorand.Reader, provider.key[:]); err == nil {
		provider.keyValid = true
	}
	return provider
}

func (p *defaultPresenceProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil || inbound.User.Email == "" {
		return session.PresenceScope{}
	}
	ip, ok := canonicalPresenceIP(inbound.CarrierSource)
	if !ok {
		return session.PresenceScope{}
	}
	principalKey, reusable := p.principalKey(inbound.User, inbound.Tag, inbound.Name)
	return session.PresenceScope{
		Subject: session.PresenceSubject{
			Email:        inbound.User.Email,
			Level:        inbound.User.Level,
			IP:           ip,
			PrincipalKey: principalKey,
			Reusable:     reusable,
		},
		Tracker: p.tracker,
	}
}

func (p *defaultPresenceProvider) principalKey(user *protocol.MemoryUser, inboundTag, inboundName string) ([32]byte, bool) {
	if !p.keyValid || user == nil || user.Account == nil {
		return p.carrierLocalPrincipal()
	}
	message := user.Account.ToProto()
	if message == nil {
		return p.carrierLocalPrincipal()
	}
	marshal := p.marshal
	if marshal == nil {
		marshal = proto.MarshalOptions{Deterministic: true}.Marshal
	}
	accountBytes, err := marshal(message)
	if err != nil {
		return p.carrierLocalPrincipal()
	}
	mac := hmac.New(sha256.New, p.key[:])
	_, _ = mac.Write([]byte(principalDomainSeparator))
	writePrincipalField(mac, []byte(message.ProtoReflect().Descriptor().FullName()))
	writePrincipalField(mac, accountBytes)
	writePrincipalField(mac, []byte(inboundTag))
	writePrincipalField(mac, []byte(inboundName))
	var principal [32]byte
	copy(principal[:], mac.Sum(nil))
	return principal, true
}

func (p *defaultPresenceProvider) carrierLocalPrincipal() ([32]byte, bool) {
	var principal [32]byte
	if p.entropy == nil {
		return principal, false
	}
	if _, err := io.ReadFull(p.entropy, principal[:]); err != nil {
		return [32]byte{}, false
	}
	return principal, false
}

func writePrincipalField(writer io.Writer, field []byte) {
	var encodedLength [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(encodedLength[:], uint64(len(field)))
	_, _ = writer.Write(encodedLength[:n])
	_, _ = writer.Write(field)
}

func canonicalPresenceIP(source net.Destination) (netip.Addr, bool) {
	if !source.IsValid() || source.Address == nil || !source.Address.Family().IsIP() {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(source.Address.IP())
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}

func formatPresenceIP(addr netip.Addr) string {
	if addr.Is6() {
		return "[" + addr.String() + "]"
	}
	return addr.String()
}

type onlinePresenceTracker struct {
	policy      policy.Manager
	stats       featurestats.Manager
	lastWarning atomic.Int64
}

func (t *onlinePresenceTracker) Prepare(subject session.PresenceSubject) session.PresenceReservation {
	if !subject.Valid() || t.policy == nil || t.stats == nil || !t.policy.ForLevel(subject.Level).Stats.UserOnline {
		return session.NoopPresenceReservation()
	}
	onlineMap, err := t.stats.GetOrRegisterOnlineMap("user>>>" + subject.Email + ">>>online")
	if err != nil || onlineMap == nil {
		t.warn("online presence map is unavailable; traffic remains untracked")
		return session.NoopPresenceReservation()
	}
	return &onlinePresenceReservation{
		onlineMap: onlineMap,
		ip:        formatPresenceIP(subject.IP),
		degraded:  t.warn,
	}
}

func (t *onlinePresenceTracker) warn(message string) {
	now := time.Now().UnixNano()
	last := t.lastWarning.Load()
	if last != 0 && now-last < int64(time.Minute) {
		return
	}
	if t.lastWarning.CompareAndSwap(last, now) {
		errors.LogWarning(context.Background(), message)
	}
}

type onlinePresenceReservation struct {
	onlineMap featurestats.OnlineMap
	ip        string
	once      sync.Once
	lease     session.PresenceLease
	degraded  func(string)
}

func (r *onlinePresenceReservation) Activate() session.PresenceLease {
	r.once.Do(func() {
		r.onlineMap.AddIP(r.ip)
		r.lease = newOnlinePresenceLease(r.onlineMap, r.ip)
	})
	if r.lease == nil {
		return session.NoopPresenceReservation().Activate()
	}
	return r.lease
}

func (r *onlinePresenceReservation) Handoff(previous session.PresenceLease) session.PresenceLease {
	r.once.Do(func() {
		if oldLease, ok := previous.(*onlinePresenceLease); ok && sameOnlineMap(oldLease.onlineMap, r.onlineMap) {
			if handoffMap, ok := r.onlineMap.(interface{ HandoffIP(string, string) }); ok && oldLease.take() {
				handoffMap.HandoffIP(oldLease.ip, r.ip)
				r.lease = newOnlinePresenceLease(r.onlineMap, r.ip)
				return
			}
		}
		r.onlineMap.AddIP(r.ip)
		r.lease = newOnlinePresenceLease(r.onlineMap, r.ip)
		if previous != nil {
			previous.Close()
		}
		if previous != nil && r.degraded != nil {
			r.degraded("online presence handoff is non-atomic for this OnlineMap implementation")
		}
	})
	if r.lease == nil {
		return session.NoopPresenceReservation().Activate()
	}
	return r.lease
}

func (r *onlinePresenceReservation) Abort() {
	r.once.Do(func() {
		r.lease = session.NoopPresenceReservation().Activate()
	})
}

type onlinePresenceLease struct {
	onlineMap featurestats.OnlineMap
	ip        string
	active    atomic.Bool
}

func newOnlinePresenceLease(onlineMap featurestats.OnlineMap, ip string) *onlinePresenceLease {
	lease := &onlinePresenceLease{onlineMap: onlineMap, ip: ip}
	lease.active.Store(true)
	return lease
}

func (l *onlinePresenceLease) take() bool {
	return l != nil && l.active.CompareAndSwap(true, false)
}

func (l *onlinePresenceLease) Close() {
	if l.take() {
		l.onlineMap.RemoveIP(l.ip)
	}
}

func sameOnlineMap(left, right featurestats.OnlineMap) bool {
	return left != nil && right != nil && reflect.ValueOf(left) == reflect.ValueOf(right)
}
