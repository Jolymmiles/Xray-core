package dispatcher

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"net/netip"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"google.golang.org/protobuf/proto"
)

const principalDomainSeparator = "xray-online-principal-v1"

type presenceDegradationReporter interface {
	warnDegraded(string)
}

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
		entropy: rand.Reader,
	}
	_, err := io.ReadFull(rand.Reader, provider.key[:])
	provider.keyValid = err == nil
	return provider
}

func (p *defaultPresenceProvider) SnapshotPresence(ctx context.Context) session.PresenceScope {
	inbound := session.InboundFromContext(ctx)
	if p == nil || inbound == nil || inbound.User == nil || inbound.User.Email == "" {
		return session.PresenceScope{}
	}
	ip := inbound.PhysicalPeer.Unmap()
	if !validPresenceIP(ip) {
		if reporter, ok := p.tracker.(presenceDegradationReporter); ok {
			reporter.warnDegraded("trusted peer unavailable")
		}
		return session.PresenceScope{}
	}
	principal, reusable := p.principalKey(inbound.User, inbound.Tag, inbound.Name)
	return session.NewPresenceScope(session.PresenceSubject{
		Email:        inbound.User.Email,
		Level:        inbound.User.Level,
		IP:           ip,
		PrincipalKey: principal,
		Reusable:     reusable,
	}, p.tracker)
}

func canonicalPresenceIP(peer net.Addr) (netip.Addr, bool) {
	return corenet.CanonicalPhysicalPeer(peer)
}

func (p *defaultPresenceProvider) principalKey(user *protocol.MemoryUser, inboundTag, inboundName string) ([32]byte, bool) {
	if p == nil || !p.keyValid || user == nil || user.Account == nil {
		return p.localPrincipal()
	}
	message := user.Account.ToProto()
	if message == nil {
		return p.localPrincipal()
	}
	marshal := p.marshal
	if marshal == nil {
		marshal = proto.MarshalOptions{Deterministic: true}.Marshal
	}
	account, err := marshal(message)
	if err != nil {
		return p.localPrincipal()
	}

	mac := hmac.New(sha256.New, p.key[:])
	_, _ = mac.Write([]byte(principalDomainSeparator))
	writePrincipalField(mac, []byte(message.ProtoReflect().Descriptor().FullName()))
	writePrincipalField(mac, account)
	writePrincipalField(mac, []byte(inboundTag))
	writePrincipalField(mac, []byte(inboundName))
	var principal [32]byte
	copy(principal[:], mac.Sum(nil))
	return principal, true
}

func (p *defaultPresenceProvider) localPrincipal() ([32]byte, bool) {
	var principal [32]byte
	if p == nil || p.entropy == nil {
		return principal, false
	}
	if _, err := io.ReadFull(p.entropy, principal[:]); err != nil {
		return [32]byte{}, false
	}
	return principal, false
}

func writePrincipalField(writer io.Writer, field []byte) {
	var length [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(length[:], uint64(len(field)))
	_, _ = writer.Write(length[:n])
	_, _ = writer.Write(field)
}
