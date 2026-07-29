package dispatcher

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var errSniffingTimeout = errors.New("timeout on sniffing")

type cachedReader struct {
	sync.Mutex
	reader   buf.TimeoutReader // *pipe.Reader or *buf.TimeoutWrapperReader
	cache    buf.MultiBuffer
	scratch  *buf.Buffer
	snapshot []byte
}

func newCachedReader(reader buf.TimeoutReader) *cachedReader {
	return &cachedReader{reader: reader}
}

func (r *cachedReader) Cache(deadline time.Duration) ([]byte, error) {
	mb, err := r.reader.ReadMultiBufferTimeout(deadline)
	if err != nil {
		return nil, err
	}
	r.Lock()
	if !mb.IsEmpty() {
		if r.cache.IsEmpty() {
			r.cache = mb
		} else {
			r.cache, _ = buf.MergeMulti(r.cache, mb)
		}
	}
	if len(r.cache) == 1 && r.cache[0] != nil {
		r.snapshot = append(r.snapshot[:0], r.cache[0].Bytes()...)
		payload := r.snapshot
		r.Unlock()
		return payload, nil
	}
	if r.scratch == nil {
		r.scratch = buf.NewWithSize(32767)
	}
	r.scratch.Clear()
	rawBytes := r.scratch.Extend(min(r.cache.Len(), r.scratch.Cap()))
	n := r.cache.Copy(rawBytes)
	r.scratch.Resize(0, int32(n))
	// Cache returns a snapshot rather than a view into cache or scratch.
	// Interrupt may release either pooled buffer as soon as this lock drops,
	// while the sniffer is still reading the returned bytes.
	r.snapshot = append(r.snapshot[:0], r.scratch.Bytes()...)
	payload := r.snapshot
	r.Unlock()
	return payload, nil
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		if r.scratch != nil {
			r.scratch.Release()
			r.scratch = nil
		}
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBufferTimeout(timeout)
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	if r.scratch != nil {
		r.scratch.Release()
		r.scratch = nil
	}
	r.Unlock()
	if p, ok := r.reader.(*pipe.Reader); ok {
		p.Interrupt()
	}
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm                 outbound.Manager
	router              routing.Router
	routePicker         routeTagPicker
	sniffingRequirement sniffingAttributeRequirement
	policy              policy.Manager
	stats               stats.Manager
	fdns                dns.FakeDNSEngine
	snifferTemplate     Sniffer
	detourCache         atomic.Pointer[detourCache]
}

type detourCacheKey struct {
	inbound  string
	outbound string
	route    uint8
}

type detourCacheEntry struct {
	key   detourCacheKey
	value string
}

type detourCache struct {
	entries []detourCacheEntry
	index   map[detourCacheKey]string
}

const detourIndexThreshold = 16

type routeTagPicker interface {
	PickRouteTag(ctx routing.Context) (outboundTag string, ruleTag string, err error)
}

type sniffingAttributeRequirement interface {
	NeedsSniffingAttributes() bool
}

func (d *DefaultDispatcher) configureSniffingAttributes(content *session.Content) {
	content.SkipSniffingAttributes = false
	requirement := d.sniffingRequirement
	if requirement == nil {
		requirement, _ = d.router.(sniffingAttributeRequirement)
	}
	if requirement != nil {
		content.SkipSniffingAttributes = !requirement.NeedsSniffingAttributes()
	}
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dc dns.Client) error {
			core.OptionalFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, pm, sm)
		}); err != nil {
			return nil, err
		}
		d.snifferTemplate = newSniffer(ctx)
		return d, nil
	}))
}

func (d *DefaultDispatcher) connectionSniffer(ctx context.Context) Sniffer {
	if d.snifferTemplate.sniffer != nil {
		return d.snifferTemplate
	}
	return newSniffer(ctx)
}

func (d *DefaultDispatcher) detour(inboundTag, outboundTag string, route int) string {
	if inboundTag == "" {
		return outboundTag
	}
	key := detourCacheKey{inbound: inboundTag, outbound: outboundTag, route: uint8(route)}
	if cache := d.detourCache.Load(); cache != nil {
		if len(cache.entries) != 0 {
			entry := cache.entries[0]
			if entry.key.route == key.route && entry.key.inbound == inboundTag && entry.key.outbound == outboundTag {
				return entry.value
			}
		}
		if cache.index != nil {
			if value, found := cache.index[key]; found {
				return value
			}
		} else {
			for _, entry := range cache.entries[1:] {
				if entry.key.route == key.route && entry.key.inbound == inboundTag && entry.key.outbound == outboundTag {
					return entry.value
				}
			}
		}
	}
	separator := " >> "
	switch route {
	case 1:
		separator = " ==> "
	case 2:
		separator = " -> "
	}
	formatted := inboundTag + separator + outboundTag
	for {
		current := d.detourCache.Load()
		if current != nil {
			if len(current.entries) != 0 {
				entry := current.entries[0]
				if entry.key.route == key.route && entry.key.inbound == inboundTag && entry.key.outbound == outboundTag {
					return entry.value
				}
			}
			if current.index != nil {
				if value, found := current.index[key]; found {
					return value
				}
			} else {
				for _, entry := range current.entries[1:] {
					if entry.key.route == key.route && entry.key.inbound == inboundTag && entry.key.outbound == outboundTag {
						return entry.value
					}
				}
			}
		}
		entryCount := 0
		if current != nil {
			entryCount = len(current.entries)
		}
		next := &detourCache{entries: make([]detourCacheEntry, entryCount+1)}
		if current != nil {
			copy(next.entries, current.entries)
		}
		next.entries[entryCount] = detourCacheEntry{key: key, value: formatted}
		if entryCount+1 >= detourIndexThreshold {
			next.index = make(map[detourCacheKey]string, entryCount)
			if current != nil && current.index != nil {
				for currentKey, value := range current.index {
					next.index[currentKey] = value
				}
			} else if current != nil {
				for _, entry := range current.entries[1:] {
					next.index[entry.key] = entry.value
				}
			}
			next.index[key] = formatted
		}
		if d.detourCache.CompareAndSwap(current, next) {
			return formatted
		}
	}
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
	d.ohm = om
	d.router = router
	d.routePicker, _ = router.(routeTagPicker)
	d.sniffingRequirement, _ = router.(sniffingAttributeRequirement)
	d.policy = pm
	d.stats = sm
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error { return nil }

func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link) {
	return d.getLinkWithInbound(ctx, session.InboundFromContext(ctx))
}

func (d *DefaultDispatcher) getLinkWithInbound(ctx context.Context, sessionInbound *session.Inbound) (*transport.Link, *transport.Link) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	if user != nil && len(user.Email) > 0 {
		p := d.policy.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := d.stats.GetOrRegisterCounter(name); c != nil {
				inboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  inboundLink.Writer,
				}
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := d.stats.GetOrRegisterCounter(name); c != nil {
				outboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  outboundLink.Writer,
				}
			}
		}

		if p.Stats.UserOnline {
			trackOnlineIP(ctx, d.stats, user.Email, sessionInbound.Source.Address.String())
		}
	}

	return inboundLink, outboundLink
}

func WrapLink(ctx context.Context, policyManager policy.Manager, statsManager stats.Manager, link *transport.Link) *transport.Link {
	return wrapLink(ctx, policyManager, statsManager, link, true)
}

func wrapLink(ctx context.Context, policyManager policy.Manager, statsManager stats.Manager, link *transport.Link, needTimeout bool) *transport.Link {
	return wrapLinkWithInbound(ctx, policyManager, statsManager, link, needTimeout, session.InboundFromContext(ctx))
}

func wrapLinkWithInbound(ctx context.Context, policyManager policy.Manager, statsManager stats.Manager, link *transport.Link, needTimeout bool, sessionInbound *session.Inbound) *transport.Link {
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	var timeoutReader *buf.TimeoutWrapperReader
	if needTimeout {
		timeoutReader = &buf.TimeoutWrapperReader{Reader: link.Reader}
		link.Reader = timeoutReader
	}

	if user != nil && len(user.Email) > 0 {
		p := policyManager.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := statsManager.GetOrRegisterCounter(name); c != nil {
				if timeoutReader == nil {
					timeoutReader = &buf.TimeoutWrapperReader{Reader: link.Reader}
					link.Reader = timeoutReader
				}
				timeoutReader.Counter = c
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := statsManager.GetOrRegisterCounter(name); c != nil {
				link.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  link.Writer,
				}
			}
		}
		if p.Stats.UserOnline {
			trackOnlineIP(ctx, statsManager, user.Email, sessionInbound.Source.Address.String())
		}
	}

	return link
}

func trackOnlineIP(ctx context.Context, sm stats.Manager, email, ip string) {
	name := "user>>>" + email + ">>>online"
	if om, _ := sm.GetOrRegisterOnlineMap(name); om != nil {
		om.AddIP(ip)
		context.AfterFunc(ctx, func() { om.RemoveIP(ip) })
	}
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination net.Destination) (string, bool) {
	protocolString, domain := "", ""
	simpleResult, simple := result.(simpleNormalizedSniffResult)
	if simple {
		protocolString, domain = simpleResult.NormalizedProtocolDomain()
	} else {
		domain = result.Domain()
	}
	if domain == "" {
		return "", false
	}
	if request.ExcludeForDomain != nil {
		normalizedDomain := domain
		if !simple {
			if normalized, ok := result.(snifferNormalizedDomain); !ok || !normalized.DomainNormalized() {
				normalizedDomain = strings.ToLower(domain)
			}
		}
		if request.ExcludeForDomain.MatchAny(normalizedDomain) {
			return domain, false
		}
	}
	if request.ExcludeForIP != nil && destination.Address.Family().IsIP() && request.ExcludeForIP.Match(destination.Address.IP()) {
		return domain, false
	}
	if !simple {
		protocolString = result.Protocol()
		if resComp, ok := result.(SnifferResultComposite); ok {
			protocolString = resComp.ProtocolForDomainResult()
		}
	}
	var resultSubset SnifferIsProtoSubsetOf
	hasResultSubset := false
	if !simple {
		resultSubset, hasResultSubset = result.(SnifferIsProtoSubsetOf)
	}
	if simple {
		switch protocolString {
		case "http1", "http2":
			if request.OverrideProtocolMask&session.SniffingOverrideHTTP != 0 {
				return domain, true
			}
		case "tls":
			if request.OverrideProtocolMask&session.SniffingOverrideTLS != 0 {
				return domain, true
			}
		}
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) || strings.HasPrefix(p, protocolString) {
			return domain, true
		}
		if p == "fakedns" && protocolString != "bittorrent" {
			if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(destination.Address) {
				errors.LogInfo(ctx, "Using sniffer ", protocolString, " since the fake DNS missed")
				return domain, true
			}
		}
		if hasResultSubset {
			if resultSubset.IsProtoSubsetOf(p) {
				return domain, true
			}
		}
	}

	return domain, false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	sessionInbound, outbounds, content, routingLink := session.ConnectionMetadataFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
		routingLink = nil
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
		routingLink = nil
	}
	d.configureSniffingAttributes(content)

	sniffingRequest := content.SniffingRequest
	inbound, outbound := d.getLinkWithInbound(ctx, sessionInbound)
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination, ob, content, routingLink)
	} else {
		go func() {
			cReader := newCachedReader(outbound.Reader.(*pipe.Reader))
			outbound.Reader = cReader
			result, err := sniff(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network, d.connectionSniffer(ctx))
			if err == nil {
				content.Protocol = result.Protocol()
				domain, override := d.shouldOverride(ctx, result, sniffingRequest, destination)
				if override {
					errors.LogInfo(ctx, "sniffed domain: ", domain)
					destination.Address = net.ParseAddress(domain)
					protocol := result.Protocol()
					if resComp, ok := result.(SnifferResultComposite); ok {
						protocol = resComp.ProtocolForDomainResult()
					}
					isFakeIP := false
					if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
						isFakeIP = true
					}
					if sniffingRequest.RouteOnly && protocol != "fakedns" && protocol != "fakedns+others" && !isFakeIP {
						ob.RouteTarget = destination
					} else {
						ob.Target = destination
					}
				}
			}
			d.routedDispatch(ctx, outbound, destination, ob, content, routingLink)
		}()
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return errors.New("Dispatcher: Invalid destination.")
	}
	sessionInbound, outbounds, content, routingLink := session.ConnectionMetadataFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
		routingLink = nil
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
		routingLink = nil
	}
	d.configureSniffingAttributes(content)
	sniffingRequest := content.SniffingRequest
	outbound = wrapLinkWithInbound(ctx, d.policy, d.stats, outbound, sniffingRequest.Enabled, sessionInbound)
	if !sniffingRequest.Enabled {
		d.routedDispatch(ctx, outbound, destination, ob, content, routingLink)
	} else {
		cReader := newCachedReader(outbound.Reader.(buf.TimeoutReader))
		outbound.Reader = cReader
		result, err := sniff(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network, d.connectionSniffer(ctx))
		if err == nil {
			content.Protocol = result.Protocol()
			domain, override := d.shouldOverride(ctx, result, sniffingRequest, destination)
			if override {
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = net.ParseAddress(domain)
				protocol := result.Protocol()
				if resComp, ok := result.(SnifferResultComposite); ok {
					protocol = resComp.ProtocolForDomainResult()
				}
				isFakeIP := false
				if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
					isFakeIP = true
				}
				if sniffingRequest.RouteOnly && protocol != "fakedns" && protocol != "fakedns+others" && !isFakeIP {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
		}
		d.routedDispatch(ctx, outbound, destination, ob, content, routingLink)
	}

	return nil
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	return sniff(ctx, cReader, metadataOnly, network, newSniffer(ctx))
}

func sniff(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network, sniffer Sniffer) (SniffResult, error) {
	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		cacheDeadline := 200 * time.Millisecond
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				cachingStartingTimeStamp := time.Now()
				payloadBytes, err := cReader.Cache(cacheDeadline)
				if err != nil {
					return nil, err
				}

				if len(payloadBytes) != 0 {
					result, err := sniffer.Sniff(ctx, payloadBytes, network)
					switch err {
					case common.ErrNoClue: // No Clue: protocol not matches, and sniffer cannot determine whether there will be a match or not
						totalAttempt++
					case protocol.ErrProtoNeedMoreData: // Protocol Need More Data: protocol matches, but need more data to complete sniffing
						// in this case, do not add totalAttempt(allow to read until timeout)
					default:
						return result, err
					}
				} else {
					totalAttempt++
				}
				cacheDeadline -= time.Since(cachingStartingTimeStamp)
				if totalAttempt >= 2 || cacheDeadline <= 0 {
					return nil, errSniffingTimeout
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination, ob *session.Outbound, content *session.Content, routingLink routing.Context) {
	var handler outbound.Handler

	if routingLink == nil {
		routingLink = routing_session.AsRoutingContext(ctx)
	}
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	if forcedOutboundTag := session.TakeForcedOutboundTagFromContent(content); forcedOutboundTag != "" {
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			if log.ShouldLog(log.Severity_Info) {
				errors.LogInfo(ctx, "taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			}
			handler = h
		} else {
			errors.LogError(ctx, "non existing tag for platform initialized detour: ", forcedOutboundTag)
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	} else if d.router != nil {
		var outTag, ruleTag string
		var err error
		picker := d.routePicker
		if picker == nil {
			picker, _ = d.router.(routeTagPicker)
		}
		if picker != nil {
			outTag, ruleTag, err = picker.PickRouteTag(routingLink)
		} else {
			var route routing.Route
			route, err = d.router.PickRoute(routingLink)
			if err == nil {
				outTag = route.GetOutboundTag()
				ruleTag = route.GetRuleTag()
			}
		}
		if err == nil {
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				if ruleTag == "" {
					if log.ShouldLog(log.Severity_Info) {
						errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
					}
				} else {
					if log.ShouldLog(log.Severity_Info) {
						errors.LogInfo(ctx, "Hit route rule: [", ruleTag, "] so taking detour [", outTag, "] for [", destination, "]")
					}
				}
				handler = h
			} else {
				errors.LogWarning(ctx, "non existing outTag: ", outTag)
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return // DO NOT CHANGE: the traffic shouldn't be processed by default outbound if the specified outbound tag doesn't exist (yet), e.g., VLESS Reverse Proxy
			}
		} else {
			if log.ShouldLog(log.Severity_Info) {
				errors.LogInfo(ctx, "default route for ", destination)
			}
		}
	}

	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		errors.LogInfo(ctx, "default outbound handler not exist")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	handlerTag := handler.Tag()
	ob.Tag = handlerTag
	if accessMessage := session.AccessMessageFromContext(ctx); accessMessage != nil {
		accessRecord := *accessMessage
		accessRecord.To = nil
		accessRecord.ToString = ""
		accessRecord.Target = log.AccessTarget{
			Network: destination.Network.SystemString(),
			Address: destination.Address,
			Port:    destination.Port.Value(),
		}
		accessRecord.HasTarget = true
		accessRecord.Component = "app/dispatcher"
		accessRecord.Inbound = inTag
		accessRecord.Outbound = handlerTag
		if tag := handlerTag; tag != "" {
			accessRecord.Detour = d.detour(inTag, tag, isPickRoute)
		}
		log.Record(&accessRecord)
	}

	handler.Dispatch(ctx, link)
}
