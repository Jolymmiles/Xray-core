package dns

import (
	"context"
	stdnetip "net/netip"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

// ResolvableContext is an implementation of routing.Context, with domain resolving capability.
type ResolvableContext struct {
	routing.Context
	dnsClient    dns.Client
	cacheIPs     []net.IP
	targetDomain string
	hasError     bool
}

// GetTargetIPs overrides original routing.Context's implementation.
func (ctx *ResolvableContext) GetTargetIPs() []net.IP {
	if len(ctx.cacheIPs) > 0 {
		return ctx.cacheIPs
	}

	if ctx.hasError {
		return nil
	}

	domain := ctx.targetDomain
	if domain == "" {
		domain = ctx.GetTargetDomain()
	}
	if len(domain) != 0 {
		ips, _, err := ctx.dnsClient.LookupIP(domain, dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		})
		if err == nil {
			ctx.cacheIPs = ips
			return ips
		}
		errors.LogInfoInner(context.Background(), err, "resolve ip for ", domain)
	}

	if ips := ctx.Context.GetTargetIPs(); len(ips) != 0 {
		ctx.cacheIPs = ips
		return ips
	}

	ctx.hasError = true
	return nil
}

// GetTargetNetIPAddr exposes the common single-address DNS result without
// converting it back through the legacy Address interface.
func (ctx *ResolvableContext) GetTargetNetIPAddr() (stdnetip.Addr, bool) {
	ips := ctx.GetTargetIPs()
	if len(ips) == 1 {
		address, ok := stdnetip.AddrFromSlice(ips[0])
		return address.Unmap(), ok
	}
	return stdnetip.Addr{}, false
}

// ContextWithDNSClient creates a new routing context with domain resolving capability.
// Resolved domain IPs can be retrieved by GetTargetIPs().
func ContextWithDNSClient(ctx routing.Context, client dns.Client) routing.Context {
	resolved := NewResolvableContext(ctx, client)
	return &resolved
}

// NewResolvableContext returns a reset value suitable for short-lived routing
// decisions whose resolved context does not need to escape the caller.
func NewResolvableContext(ctx routing.Context, client dns.Client) ResolvableContext {
	return ResolvableContext{Context: ctx, dnsClient: client}
}

// Reset prepares a reusable context for another independent routing decision.
func (ctx *ResolvableContext) Reset(base routing.Context, client dns.Client) {
	*ctx = ResolvableContext{Context: base, dnsClient: client}
}

// ResetWithDomain also supplies the already-read target domain so DNS fallback
// does not have to traverse the routing context again.
func (ctx *ResolvableContext) ResetWithDomain(base routing.Context, client dns.Client, domain string) {
	*ctx = ResolvableContext{Context: base, dnsClient: client, targetDomain: domain}
}
