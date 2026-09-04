package tls

import (
	"container/list"
	"context"
	"crypto/tls"
	"net"
	"reflect"
	"slices"
	"sync"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/errors"
)

const (
	configSessionCacheCapacity    = 128
	sessionCacheCapacity          = 128
	uTLSSessionCacheScopeCapacity = 256
)

type configSessionCacheEntry struct {
	config *Config
	cache  tls.ClientSessionCache
}

var configSessionCaches = struct {
	sync.Mutex
	entries map[*Config]*list.Element
	lru     list.List
}{
	entries: make(map[*Config]*list.Element),
}

func clientSessionCache(config *Config) tls.ClientSessionCache {
	configSessionCaches.Lock()
	defer configSessionCaches.Unlock()

	if element := configSessionCaches.entries[config]; element != nil {
		configSessionCaches.lru.MoveToFront(element)
		return element.Value.(*configSessionCacheEntry).cache
	}

	entry := &configSessionCacheEntry{
		config: config,
		cache:  tls.NewLRUClientSessionCache(sessionCacheCapacity),
	}
	element := configSessionCaches.lru.PushFront(entry)
	configSessionCaches.entries[config] = element
	if configSessionCaches.lru.Len() > configSessionCacheCapacity {
		oldest := configSessionCaches.lru.Back()
		configSessionCaches.lru.Remove(oldest)
		delete(configSessionCaches.entries, oldest.Value.(*configSessionCacheEntry).config)
	}
	return entry.cache
}

type clientSessionResumption struct {
	configured bool
	source     tls.ClientSessionCache
}

func newClientSessionResumption(config *tls.Config) clientSessionResumption {
	resumption := clientSessionResumption{
		configured: config.ClientSessionCache != nil && !config.SessionTicketsDisabled,
	}
	if !resumption.configured {
		return resumption
	}
	cacheValue := reflect.ValueOf(config.ClientSessionCache)
	if cacheValue.Kind() == reflect.Pointer && !cacheValue.IsNil() {
		resumption.source = config.ClientSessionCache
	}
	return resumption
}

func (r clientSessionResumption) enabled() bool {
	return r.configured
}

func (r clientSessionResumption) client(connection net.Conn, config *utls.Config, fingerprint utls.ClientHelloID) *utls.UConn {
	if r.source != nil {
		if spec, eligible := clientHelloSpecForResumption(fingerprint); eligible {
			config.ClientSessionCache = r.sessionCache(fingerprint)
			conn := utls.UClient(connection, config, utls.HelloCustom)
			if err := conn.ApplyPreset(spec); err == nil {
				return conn
			}
			config.ClientSessionCache = nil
		}

		// Falling back keeps the stock ClientHello. Forcing resumption here
		// would add extensions the impersonated client does not send.
		config.OmitEmptyPsk = false
		reportUnresumableFingerprint(fingerprint)
	}
	return utls.UClient(connection, config, fingerprint)
}

type uTLSSessionCacheScope struct {
	// Keep the pointer-backed identity alive while tickets can reference it.
	source      tls.ClientSessionCache
	fingerprint string
}

type uTLSSessionCacheEntry struct {
	scope uTLSSessionCacheScope
	cache utls.ClientSessionCache
}

var uTLSSessionCaches = struct {
	sync.Mutex
	entries map[uTLSSessionCacheScope]*list.Element
	lru     list.List
}{
	entries: make(map[uTLSSessionCacheScope]*list.Element),
}

func (r clientSessionResumption) sessionCache(fingerprint utls.ClientHelloID) utls.ClientSessionCache {
	scope := uTLSSessionCacheScope{
		source:      r.source,
		fingerprint: fingerprint.Str(),
	}
	uTLSSessionCaches.Lock()
	defer uTLSSessionCaches.Unlock()

	if element := uTLSSessionCaches.entries[scope]; element != nil {
		uTLSSessionCaches.lru.MoveToFront(element)
		return element.Value.(*uTLSSessionCacheEntry).cache
	}
	entry := &uTLSSessionCacheEntry{
		scope: scope,
		cache: newSerializingUTLSSessionCache(),
	}
	element := uTLSSessionCaches.lru.PushFront(entry)
	uTLSSessionCaches.entries[scope] = element
	if uTLSSessionCaches.lru.Len() > uTLSSessionCacheScopeCapacity {
		oldest := uTLSSessionCaches.lru.Back()
		uTLSSessionCaches.lru.Remove(oldest)
		delete(uTLSSessionCaches.entries, oldest.Value.(*uTLSSessionCacheEntry).scope)
	}
	return entry.cache
}

type serializingUTLSSessionCache struct {
	sync.Mutex
	cache utls.ClientSessionCache
}

func newSerializingUTLSSessionCache() utls.ClientSessionCache {
	return &serializingUTLSSessionCache{
		cache: utls.NewLRUClientSessionCache(sessionCacheCapacity),
	}
}

func (c *serializingUTLSSessionCache) Get(sessionKey string) (*utls.ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	session, ok := c.cache.Get(sessionKey)
	if !ok {
		return nil, false
	}
	c.cache.Put(sessionKey, nil)
	cloned := cloneUTLSSession(session)
	return cloned, cloned != nil
}

func (c *serializingUTLSSessionCache) Put(sessionKey string, session *utls.ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if session == nil {
		c.cache.Put(sessionKey, nil)
		return
	}
	if cloned := cloneUTLSSession(session); cloned != nil {
		c.cache.Put(sessionKey, cloned)
	}
}

func cloneUTLSSession(session *utls.ClientSessionState) *utls.ClientSessionState {
	ticket, state, err := session.ResumptionState()
	if err != nil || state == nil {
		return nil
	}
	serialized, err := state.Bytes()
	if err != nil {
		return nil
	}
	clonedState, err := utls.ParseSessionState(serialized)
	if err != nil {
		return nil
	}
	cloned, err := utls.NewResumptionState(slices.Clone(ticket), clonedState)
	if err != nil {
		return nil
	}
	return cloned
}

var reportedUnresumableFingerprints sync.Map

// reportUnresumableFingerprint logs the intentional fallback once per
// fingerprint, avoiding a per-connection log flood.
func reportUnresumableFingerprint(fingerprint utls.ClientHelloID) {
	name := fingerprint.Str()
	if _, reported := reportedUnresumableFingerprints.LoadOrStore(name, struct{}{}); reported {
		return
	}
	errors.LogInfo(context.Background(), "TLS session resumption is unavailable for fingerprint ", name,
		": its ClientHello does not advertise session_ticket and psk_key_exchange_modes, ",
		"and adding them would not match the impersonated client")
}

// SupportsSessionResumption reports whether a resumption PSK can be offered
// under the given fingerprint without altering its ClientHello.
func SupportsSessionResumption(fingerprint utls.ClientHelloID) bool {
	_, eligible := clientHelloSpecForResumption(fingerprint)
	return eligible
}

// clientHelloSpecForResumption returns a ClientHello template able to carry a
// resumption PSK, or false when preserving the stock fingerprint wins.
func clientHelloSpecForResumption(fingerprint utls.ClientHelloID) (*utls.ClientHelloSpec, bool) {
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return nil, false
	}
	return resumptionSpec(spec)
}

// resumptionSpec accepts only templates that already advertise session_ticket
// and psk_key_exchange_modes. It appends pre_shared_key last as required by RFC
// 8446 section 4.2.11; OmitEmptyPsk keeps it off the wire until a ticket exists.
func resumptionSpec(spec utls.ClientHelloSpec) (*utls.ClientHelloSpec, bool) {
	hasPSKExchangeModes := false
	hasSessionTicket := false
	for _, extension := range spec.Extensions {
		switch extension.(type) {
		case utls.PreSharedKeyExtension:
			return nil, false
		case *utls.PSKKeyExchangeModesExtension:
			hasPSKExchangeModes = true
		case utls.ISessionTicketExtension:
			hasSessionTicket = true
		}
	}
	if !hasSessionTicket || !hasPSKExchangeModes {
		return nil, false
	}

	// UTLSIdToSpec may return a slice sharing storage with a package template.
	extensions := make([]utls.TLSExtension, len(spec.Extensions), len(spec.Extensions)+1)
	copy(extensions, spec.Extensions)
	spec.Extensions = append(extensions, &utls.UtlsPreSharedKeyExtension{})
	return &spec, true
}
