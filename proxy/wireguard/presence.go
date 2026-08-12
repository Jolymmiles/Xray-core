package wireguard

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/session"
	"golang.zx2c4.com/wireguard/tun"
)

type authenticatedTun struct {
	tun.Device
	observe func([][]byte, int)
}

func (t *authenticatedTun) Write(bufs [][]byte, offset int) (int, error) {
	if t.observe != nil {
		t.observe(bufs, offset)
	}
	return t.Device.Write(bufs, offset)
}

// wireGuardPresence binds authenticated peers to outer endpoints and owns one
// lease per committed gVisor flow. Endpoint bindings own no lease themselves.
type wireGuardPresence struct {
	mu      sync.Mutex
	peers   map[[32]byte]*wireGuardPeerPresence
	blocked map[[32]byte]struct{}
	closed  bool
}

func newWireGuardPresence() *wireGuardPresence {
	return &wireGuardPresence{
		peers:   make(map[[32]byte]*wireGuardPeerPresence),
		blocked: make(map[[32]byte]struct{}),
	}
}

func (p *wireGuardPresence) Allow(pub [32]byte) {
	p.mu.Lock()
	delete(p.blocked, pub)
	p.mu.Unlock()
}

func (p *wireGuardPresence) Observe(pub [32]byte, observation uint64, ip netip.Addr, scope session.PresenceScope) {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	if _, blocked := p.blocked[pub]; blocked {
		p.mu.Unlock()
		return
	}
	peer := p.peers[pub]
	if peer == nil {
		peer = newWireGuardPeerPresence()
		p.peers[pub] = peer
	}
	p.mu.Unlock()
	peer.observe(observation, ip, scope)
}

func (p *wireGuardPresence) Open(pub [32]byte) *wireGuardFlow {
	p.mu.Lock()
	peer := p.peers[pub]
	closed := p.closed
	p.mu.Unlock()
	if closed || peer == nil {
		return nil
	}
	return peer.open()
}

func (p *wireGuardPresence) Remove(pub [32]byte) {
	p.mu.Lock()
	p.blocked[pub] = struct{}{}
	peer := p.peers[pub]
	delete(p.peers, pub)
	p.mu.Unlock()
	if peer != nil {
		peer.close()
	}
}

func (p *wireGuardPresence) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	peers := make([]*wireGuardPeerPresence, 0, len(p.peers))
	for _, peer := range p.peers {
		peers = append(peers, peer)
	}
	clear(p.peers)
	p.mu.Unlock()
	for _, peer := range peers {
		peer.close()
	}
}

type wireGuardPeerPresence struct {
	mu         sync.Mutex
	cond       *sync.Cond
	observed   uint64
	generation uint64
	ip         netip.Addr
	scope      session.PresenceScope
	flows      map[*wireGuardFlow]struct{}
	admitting  int
	rebinding  bool
	closed     bool
}

func newWireGuardPeerPresence() *wireGuardPeerPresence {
	peer := &wireGuardPeerPresence{flows: make(map[*wireGuardFlow]struct{})}
	peer.cond = sync.NewCond(&peer.mu)
	return peer
}

func (p *wireGuardPeerPresence) open() *wireGuardFlow {
	p.mu.Lock()
	for p.rebinding && !p.closed {
		p.cond.Wait()
	}
	if p.closed || !p.ip.IsValid() {
		p.mu.Unlock()
		return nil
	}
	generation := p.generation
	scope := p.scope
	p.admitting++
	p.mu.Unlock()

	lease := scope.Prepare().Activate()
	flow := &wireGuardFlow{peer: p, lease: lease, generation: generation}
	p.mu.Lock()
	p.admitting--
	if p.closed || p.generation != generation {
		p.cond.Broadcast()
		p.mu.Unlock()
		lease.Close()
		return p.open()
	}
	p.flows[flow] = struct{}{}
	p.cond.Broadcast()
	p.mu.Unlock()
	return flow
}

func (p *wireGuardPeerPresence) observe(observation uint64, ip netip.Addr, scope session.PresenceScope) {
	p.mu.Lock()
	for p.rebinding && !p.closed {
		p.cond.Wait()
	}
	if p.closed || observation <= p.observed {
		p.mu.Unlock()
		return
	}
	for p.admitting != 0 && !p.closed {
		p.cond.Wait()
	}
	if p.closed || observation <= p.observed {
		p.mu.Unlock()
		return
	}
	if p.ip == ip {
		p.observed = observation
		p.scope = scope
		p.mu.Unlock()
		return
	}
	if len(p.flows) == 0 {
		p.observed = observation
		p.generation++
		p.ip = ip
		p.scope = scope
		p.mu.Unlock()
		return
	}
	p.rebinding = true
	flows := make([]*wireGuardFlow, 0, len(p.flows))
	leases := make([]session.PresenceLease, 0, len(p.flows))
	for flow := range p.flows {
		flows = append(flows, flow)
		leases = append(leases, flow.lease)
	}
	p.mu.Unlock()

	replacements := scope.Prepare().HandoffAll(leases)
	p.mu.Lock()
	if p.closed || len(replacements) != len(flows) {
		p.rebinding = false
		p.cond.Broadcast()
		p.mu.Unlock()
		for _, lease := range replacements {
			lease.Close()
		}
		return
	}
	p.generation++
	for index, flow := range flows {
		flow.lease = replacements[index]
		flow.generation = p.generation
	}
	p.observed = observation
	p.ip = ip
	p.scope = scope
	p.rebinding = false
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *wireGuardPeerPresence) close() {
	p.mu.Lock()
	p.closed = true
	for p.rebinding || p.admitting != 0 {
		p.cond.Wait()
	}
	flows := make([]*wireGuardFlow, 0, len(p.flows))
	for flow := range p.flows {
		flows = append(flows, flow)
		flow.closed = true
	}
	clear(p.flows)
	p.mu.Unlock()
	for _, flow := range flows {
		flow.lease.Close()
	}
}

type wireGuardFlow struct {
	peer       *wireGuardPeerPresence
	lease      session.PresenceLease
	generation uint64
	closed     bool
	once       sync.Once
}

func (f *wireGuardFlow) Close() {
	if f == nil {
		return
	}
	f.once.Do(func() {
		p := f.peer
		p.mu.Lock()
		for p.rebinding {
			p.cond.Wait()
		}
		if f.closed {
			p.mu.Unlock()
			return
		}
		f.closed = true
		delete(p.flows, f)
		lease := f.lease
		p.mu.Unlock()
		lease.Close()
	})
}

type wireGuardPeerState struct {
	pub      [32]byte
	endpoint netip.AddrPort
	allowed  []netip.Prefix
}

// authenticatedPeerState resolves the same longest-prefix peer selected by
// WireGuard and returns only its server-observed outer endpoint.
func authenticatedPeerState(state string, inner netip.Addr) ([32]byte, netip.AddrPort, bool) {
	var peers []wireGuardPeerState
	var current *wireGuardPeerState
	scanner := bufio.NewScanner(strings.NewReader(state))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		switch key {
		case "public_key":
			bytes, err := hex.DecodeString(value)
			if err != nil || len(bytes) != 32 {
				current = nil
				continue
			}
			var pub [32]byte
			copy(pub[:], bytes)
			peers = append(peers, wireGuardPeerState{pub: pub})
			current = &peers[len(peers)-1]
		case "endpoint":
			if current != nil {
				current.endpoint, _ = netip.ParseAddrPort(value)
			}
		case "allowed_ip":
			if current != nil {
				if prefix, err := netip.ParsePrefix(value); err == nil {
					current.allowed = append(current.allowed, prefix)
				}
			}
		}
	}
	bestBits := -1
	var best wireGuardPeerState
	for _, peer := range peers {
		if !peer.endpoint.IsValid() {
			continue
		}
		for _, prefix := range peer.allowed {
			if prefix.Contains(inner) && prefix.Bits() > bestBits {
				bestBits = prefix.Bits()
				best = peer
			}
		}
	}
	if bestBits < 0 {
		return [32]byte{}, netip.AddrPort{}, false
	}
	return best.pub, best.endpoint, true
}

func encodeWireGuardKey(pub [32]byte) string {
	return hex.EncodeToString(pub[:])
}
