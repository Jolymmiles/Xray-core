package session

import (
	"context"
	"sync"
	_ "unsafe"

	"github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

//go:linkname IndependentCancelCtx context.newCancelCtx
func IndependentCancelCtx(parent context.Context) context.Context

const (
	inboundSessionKey         ctx.SessionKey = 1
	outboundSessionKey        ctx.SessionKey = 2
	contentSessionKey         ctx.SessionKey = 3
	isReverseMuxKey           ctx.SessionKey = 4  // is reverse mux
	sockoptSessionKey         ctx.SessionKey = 5  // used by dokodemo to only receive sockopt.Mark
	trackedConnectionErrorKey ctx.SessionKey = 6  // used by observer to get outbound error
	dispatcherKey             ctx.SessionKey = 7  // used by ss2022 inbounds to get dispatcher
	timeoutOnlyKey            ctx.SessionKey = 8  // mux context's child contexts to only cancel when its own traffic times out
	allowedNetworkKey         ctx.SessionKey = 9  // muxcool server control incoming request tcp/udp
	fullHandlerKey            ctx.SessionKey = 10 // outbound gets full handler
	mitmAlpn11Key             ctx.SessionKey = 11 // used by TLS dialer
	mitmServerNameKey         ctx.SessionKey = 12 // used by TLS dialer

	streamSettingsKey ctx.SessionKey = 13
	routingContextKey ctx.SessionKey = 14
)

type connectionContext struct {
	context.Context
	id            ctx.ID
	inbound       Inbound
	outbound      Outbound
	content       Content
	outbounds     [1]*Outbound
	accessMessage *log.AccessMessage
}

type metadataContext struct {
	context.Context
	key   ctx.SessionKey
	value any
}

var connectionContextPool sync.Pool

func (c *metadataContext) Value(key any) any {
	if sessionKey, ok := key.(ctx.SessionKey); ok {
		if sessionKey == routingContextKey {
			return nil
		}
		if sessionKey == c.key {
			return c.value
		}
	}
	return c.Context.Value(key)
}

func (c *connectionContext) Value(key any) any {
	if log.IsAccessMessageKey(key) {
		return c.accessMessage
	}
	if ctx.IsIDKey(key) {
		return c.id
	}
	sessionKey, ok := key.(ctx.SessionKey)
	if ok {
		switch sessionKey {
		case inboundSessionKey:
			return &c.inbound
		case outboundSessionKey:
			return c.outbounds[:]
		case contentSessionKey:
			return &c.content
		case routingContextKey:
			return c
		}
	}
	return c.Context.Value(key)
}

func (c *connectionContext) SetAccessMessage(message *log.AccessMessage) {
	c.accessMessage = message
}

func (c *connectionContext) GetAccessMessage() *log.AccessMessage {
	return c.accessMessage
}

// ConnectionMetadataFromContext returns the metadata read together by the
// dispatcher. The standard connection context needs only one type assertion;
// wrapper contexts retain the individual lookup semantics.
func ConnectionMetadataFromContext(parent context.Context) (*Inbound, []*Outbound, *Content, routing.Context) {
	if combined, ok := parent.(*connectionContext); ok {
		return &combined.inbound, combined.outbounds[:], &combined.content, combined
	}
	return InboundFromContext(parent), OutboundsFromContext(parent), ContentFromContext(parent), RoutingContextFromContext(parent)
}

// AccessMessageFromContext avoids the generic carrier lookup on the standard
// per-connection context while preserving context wrapper compatibility.
func AccessMessageFromContext(parent context.Context) *log.AccessMessage {
	if combined, ok := parent.(*connectionContext); ok {
		return combined.accessMessage
	}
	return log.AccessMessageFromContext(parent)
}

// ContextWithAccessMessage sets access metadata directly on the standard
// connection context and preserves generic context behavior for wrappers.
func ContextWithAccessMessage(parent context.Context, message *log.AccessMessage) context.Context {
	if message.SessionID == 0 {
		message.SessionID = uint32(ctx.IDFromContext(parent))
	}
	if combined, ok := parent.(*connectionContext); ok {
		combined.accessMessage = message
		return parent
	}
	return log.ContextWithAccessMessage(parent, message)
}

// RoutingContextFromContext returns the allocation-free routing view carried
// by a connection context, including through intervening context wrappers.
func RoutingContextFromContext(parent context.Context) routing.Context {
	if combined, ok := parent.(*connectionContext); ok {
		return combined
	}
	routingContext, _ := parent.Value(routingContextKey).(routing.Context)
	return routingContext
}

func (c *connectionContext) GetInboundTag() string { return c.inbound.Tag }

func (c *connectionContext) GetSourceIPs() []net.IP {
	if !c.inbound.Source.IsValid() || !c.inbound.Source.Address.Family().IsIP() {
		return nil
	}
	return []net.IP{c.inbound.Source.Address.IP()}
}

func (c *connectionContext) GetSourcePort() net.Port {
	if !c.inbound.Source.IsValid() {
		return 0
	}
	return c.inbound.Source.Port
}

func (c *connectionContext) GetTargetIPs() []net.IP {
	if !c.outbound.Target.IsValid() || !c.outbound.Target.Address.Family().IsIP() {
		return nil
	}
	return []net.IP{c.outbound.Target.Address.IP()}
}

func (c *connectionContext) GetTargetPort() net.Port {
	if !c.outbound.Target.IsValid() {
		return 0
	}
	return c.outbound.Target.Port
}

func (c *connectionContext) GetLocalIPs() []net.IP {
	if !c.inbound.Local.IsValid() || !c.inbound.Local.Address.Family().IsIP() {
		return nil
	}
	return []net.IP{c.inbound.Local.Address.IP()}
}

func (c *connectionContext) GetLocalPort() net.Port {
	if !c.inbound.Local.IsValid() {
		return 0
	}
	return c.inbound.Local.Port
}

func (c *connectionContext) GetTargetDomain() string {
	destination := c.outbound.RouteTarget
	if destination.IsValid() && destination.Address.Family().IsDomain() {
		return destination.Address.Domain()
	}
	destination = c.outbound.Target
	if !destination.IsValid() || !destination.Address.Family().IsDomain() {
		return ""
	}
	return destination.Address.Domain()
}

func (c *connectionContext) GetNetwork() net.Network { return c.outbound.Target.Network }
func (c *connectionContext) GetProtocol() string     { return c.content.Protocol }

func (c *connectionContext) GetUser() string {
	if c.inbound.User == nil {
		return ""
	}
	return c.inbound.User.Email
}

func (c *connectionContext) GetVlessRoute() net.Port { return c.inbound.VlessRoute }
func (c *connectionContext) GetAttributes() map[string]string {
	return c.content.Attributes
}
func (c *connectionContext) GetSkipDNSResolve() bool { return c.content.SkipDNSResolve }

func (c *connectionContext) GetSourceAddress() net.Address { return c.inbound.Source.Address }
func (c *connectionContext) GetTargetAddress() net.Address { return c.outbound.Target.Address }
func (c *connectionContext) GetLocalAddress() net.Address  { return c.inbound.Local.Address }

// ContextWithConnection installs the per-connection metadata used by inbound
// workers in one context node instead of a chain of independent value nodes.
func ContextWithConnection(parent context.Context, id ctx.ID, inbound Inbound, outbound Outbound, content Content) context.Context {
	combined := &connectionContext{
		Context:  parent,
		id:       id,
		inbound:  inbound,
		outbound: outbound,
		content:  content,
	}
	combined.outbounds[0] = &combined.outbound
	return combined
}

// NewPooledConnectionContext installs connection metadata in a recyclable
// context whose synchronous owner must release it after all users return.
func NewPooledConnectionContext(parent context.Context, id ctx.ID, inbound Inbound, outbound Outbound, content Content) context.Context {
	combined, _ := connectionContextPool.Get().(*connectionContext)
	if combined == nil {
		combined = new(connectionContext)
	}
	combined.Context = parent
	combined.id = id
	combined.inbound = inbound
	combined.outbound = outbound
	combined.content = content
	combined.outbounds[0] = &combined.outbound
	return combined
}

// ReleasePooledConnectionContext clears retained per-connection state.
func ReleasePooledConnectionContext(parent context.Context) {
	combined, ok := parent.(*connectionContext)
	if !ok || combined == nil {
		return
	}
	*combined = connectionContext{}
	connectionContextPool.Put(combined)
}

func ContextWithInbound(ctx context.Context, inbound *Inbound) context.Context {
	return &metadataContext{Context: ctx, key: inboundSessionKey, value: inbound}
}

func InboundFromContext(ctx context.Context) *Inbound {
	if combined, ok := ctx.(*connectionContext); ok {
		return &combined.inbound
	}
	if inbound, ok := ctx.Value(inboundSessionKey).(*Inbound); ok {
		return inbound
	}
	return nil
}

func ContextWithOutbounds(ctx context.Context, outbounds []*Outbound) context.Context {
	return &metadataContext{Context: ctx, key: outboundSessionKey, value: outbounds}
}

func SubContextFromMuxInbound(ctx context.Context) context.Context {
	newOutbounds := []*Outbound{{}}

	content := ContentFromContext(ctx)
	newContent := Content{}
	if content != nil {
		newContent = *content
		if content.Attributes != nil {
			panic("content.Attributes != nil")
		}
	}
	return ContextWithContent(ContextWithOutbounds(ctx, newOutbounds), &newContent)
}

func OutboundsFromContext(ctx context.Context) []*Outbound {
	if combined, ok := ctx.(*connectionContext); ok {
		return combined.outbounds[:]
	}
	if combined, ok := ctx.Value(routingContextKey).(*connectionContext); ok {
		return combined.outbounds[:]
	}
	if outbounds, ok := ctx.Value(outboundSessionKey).([]*Outbound); ok {
		return outbounds
	}
	return nil
}

func ContextWithContent(ctx context.Context, content *Content) context.Context {
	return &metadataContext{Context: ctx, key: contentSessionKey, value: content}
}

func ContentFromContext(ctx context.Context) *Content {
	if combined, ok := ctx.(*connectionContext); ok {
		return &combined.content
	}
	if content, ok := ctx.Value(contentSessionKey).(*Content); ok {
		return content
	}
	return nil
}

func ContextWithIsReverseMux(ctx context.Context, isReverseMux bool) context.Context {
	return context.WithValue(ctx, isReverseMuxKey, isReverseMux)
}

func IsReverseMuxFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(isReverseMuxKey).(bool); ok {
		return val
	}
	return false
}

func ContextWithSockopt(ctx context.Context, s *Sockopt) context.Context {
	return context.WithValue(ctx, sockoptSessionKey, s)
}

func SockoptFromContext(ctx context.Context) *Sockopt {
	if sockopt, ok := ctx.Value(sockoptSessionKey).(*Sockopt); ok {
		return sockopt
	}
	return nil
}

const forcedOutboundTagAttribute = "forcedOutboundTag"

func GetForcedOutboundTagFromContext(ctx context.Context) string {
	content := ContentFromContext(ctx)
	if content == nil {
		return ""
	}
	return content.Attribute(forcedOutboundTagAttribute)
}

// TakeForcedOutboundTagFromContent returns and clears a one-shot forced route.
func TakeForcedOutboundTagFromContent(content *Content) string {
	if content == nil {
		return ""
	}
	tag := content.Attribute(forcedOutboundTagAttribute)
	if tag != "" {
		content.SetAttribute(forcedOutboundTagAttribute, "")
	}
	return tag
}

func SetForcedOutboundTagToContext(ctx context.Context, tag string) context.Context {
	content := ContentFromContext(ctx)
	if content == nil {
		content = new(Content)
		ctx = ContextWithContent(ctx, content)
	}
	content.SetAttribute(forcedOutboundTagAttribute, tag)
	return ctx
}

type TrackedRequestErrorFeedback interface {
	SubmitError(err error)
}

func SubmitOutboundErrorToOriginator(ctx context.Context, err error) {
	if errorTracker := ctx.Value(trackedConnectionErrorKey); errorTracker != nil {
		errorTracker := errorTracker.(TrackedRequestErrorFeedback)
		errorTracker.SubmitError(err)
	}
}

func TrackedConnectionError(ctx context.Context, tracker TrackedRequestErrorFeedback) context.Context {
	return context.WithValue(ctx, trackedConnectionErrorKey, tracker)
}

func ContextWithDispatcher(ctx context.Context, dispatcher routing.Dispatcher) context.Context {
	return context.WithValue(ctx, dispatcherKey, dispatcher)
}

func DispatcherFromContext(ctx context.Context) routing.Dispatcher {
	if dispatcher, ok := ctx.Value(dispatcherKey).(routing.Dispatcher); ok {
		return dispatcher
	}
	return nil
}

func ContextWithTimeoutOnly(ctx context.Context, only bool) context.Context {
	return context.WithValue(ctx, timeoutOnlyKey, only)
}

func TimeoutOnlyFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(timeoutOnlyKey).(bool); ok {
		return val
	}
	return false
}

func ContextWithAllowedNetwork(ctx context.Context, network net.Network) context.Context {
	return context.WithValue(ctx, allowedNetworkKey, network)
}

func AllowedNetworkFromContext(ctx context.Context) net.Network {
	if val, ok := ctx.Value(allowedNetworkKey).(net.Network); ok {
		return val
	}
	return net.Network_Unknown
}

func ContextWithFullHandler(ctx context.Context, handler outbound.Handler) context.Context {
	return context.WithValue(ctx, fullHandlerKey, handler)
}

func FullHandlerFromContext(ctx context.Context) outbound.Handler {
	if val, ok := ctx.Value(fullHandlerKey).(outbound.Handler); ok {
		return val
	}
	return nil
}

func ContextWithMitmAlpn11(ctx context.Context, alpn11 bool) context.Context {
	return context.WithValue(ctx, mitmAlpn11Key, alpn11)
}

func MitmAlpn11FromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(mitmAlpn11Key).(bool); ok {
		return val
	}
	return false
}

func ContextWithMitmServerName(ctx context.Context, serverName string) context.Context {
	return context.WithValue(ctx, mitmServerNameKey, serverName)
}

func MitmServerNameFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(mitmServerNameKey).(string); ok {
		return val
	}
	return ""
}

func ContextWithStreamSettings(ctx context.Context, streamSettings any) context.Context {
	return context.WithValue(ctx, streamSettingsKey, streamSettings)
}

func StreamSettingsFromContext(ctx context.Context) any {
	return ctx.Value(streamSettingsKey)
}
