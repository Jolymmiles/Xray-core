package router

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/geodata/strmatcher"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
)

// Router is an implementation of routing.Router.
type Router struct {
	domainStrategy      Config_DomainStrategy
	rules               []*Rule
	domainOnlyRules     int
	domainRuleIndex     *strmatcher.MphMatcherGroup
	nonAggregateRules   []indexedRule
	simpleTargetIPRules bool
	balancers           map[string]*Balancer
	dns                 dns.Client

	ctx                     context.Context
	ohm                     outbound.Manager
	dispatcher              routing.Dispatcher
	mu                      sync.Mutex
	resolvableContexts      sync.Pool
	needsSniffingAttributes atomic.Bool
}

type indexedRule struct {
	index int
	rule  *Rule
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
	ruleTag           string
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	r.domainStrategy = config.DomainStrategy
	r.dns = d
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher
	r.needsSniffingAttributes.Store(false)

	r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
	for _, rule := range config.BalancingRule {
		balancer, err := rule.Build(ohm, dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(ctx)
		r.balancers[rule.Tag] = balancer
	}

	r.rules = make([]*Rule, 0, len(config.Rule))
	for _, rule := range config.Rule {
		cond, err := rule.BuildCondition()
		if err != nil {
			r.closeWebhooks()
			return err
		}
		rr := &Rule{
			Condition:       cond,
			Tag:             rule.GetTag(),
			RuleTag:         rule.GetRuleTag(),
			needsTargetIPs:  routingRuleNeedsTargetIPs(rule),
			needsAttributes: len(rule.GetAttributes()) != 0,
		}
		rr.domainMatcher, _ = cond.(*DomainMatcher)
		rr.targetIPMatcher, _ = cond.(*IPMatcher)
		if rr.domainMatcher != nil {
			rr.domainAggregate = aggregateDomainMatchers(rule)
		}
		if rr.needsAttributes {
			r.needsSniffingAttributes.Store(true)
		}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				r.closeWebhooks()
				return err
			}
			rr.Webhook = notifier
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				if rr.Webhook != nil {
					rr.Webhook.Close()
				}
				r.closeWebhooks()
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		r.rules = append(r.rules, rr)
	}
	r.updateDomainOnlyRuleCount()

	return nil
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	originalCtx := ctx
	rule, ctx, err := r.pickRouteInternal(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := rule.GetTag()
	if err != nil {
		return nil, err
	}
	if rule.Webhook != nil {
		rule.Webhook.Fire(originalCtx, tag)
	}
	return &Route{Context: ctx, outboundTag: tag, ruleTag: rule.RuleTag}, nil
}

// PickRouteTag returns the part of a route decision used by the dispatcher
// without allocating a Route wrapper. PickRoute remains the stable feature API
// for callers that need the resolved routing context or group tags.
func (r *Router) PickRouteTag(ctx routing.Context) (outboundTag string, ruleTag string, err error) {
	originalCtx := ctx
	var rule *Rule
	if r.domainStrategy == Config_IpIfNonMatch {
		rule, err = r.pickRouteTagIPIfNonMatch(ctx)
	} else {
		rule, _, err = r.pickRouteInternal(ctx)
	}
	if err != nil {
		return "", "", err
	}
	tag, err := rule.GetTag()
	if err != nil {
		return "", "", err
	}
	if rule.Webhook != nil {
		rule.Webhook.Fire(originalCtx, tag)
	}
	return tag, rule.RuleTag, nil
}

// AddRule implements routing.Router.
func (r *Router) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	inst, err := config.GetInstance()
	if err != nil {
		return err
	}
	if c, ok := inst.(*Config); ok {
		return r.ReloadRules(c, shouldAppend)
	}
	return errors.New("AddRule: config type error")
}

func (r *Router) ReloadRules(config *Config, shouldAppend bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !shouldAppend {
		for _, rule := range r.rules {
			if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
		r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
		r.rules = make([]*Rule, 0, len(config.Rule))
		r.needsSniffingAttributes.Store(false)
	}
	for _, rule := range config.BalancingRule {
		_, found := r.balancers[rule.Tag]
		if found {
			return errors.New("duplicate balancer tag")
		}
		balancer, err := rule.Build(r.ohm, r.dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(r.ctx)
		r.balancers[rule.Tag] = balancer
	}

	startIdx := len(r.rules)
	closeNewWebhooks := func() {
		for i := startIdx; i < len(r.rules); i++ {
			if r.rules[i].Webhook != nil {
				r.rules[i].Webhook.Close()
			}
		}
		r.rules = r.rules[:startIdx]
	}

	for _, rule := range config.Rule {
		if r.RuleExists(rule.GetRuleTag()) {
			closeNewWebhooks()
			return errors.New("duplicate ruleTag ", rule.GetRuleTag())
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			closeNewWebhooks()
			return err
		}
		rr := &Rule{
			Condition:       cond,
			Tag:             rule.GetTag(),
			RuleTag:         rule.GetRuleTag(),
			needsTargetIPs:  routingRuleNeedsTargetIPs(rule),
			needsAttributes: len(rule.GetAttributes()) != 0,
		}
		rr.domainMatcher, _ = cond.(*DomainMatcher)
		rr.targetIPMatcher, _ = cond.(*IPMatcher)
		if rr.domainMatcher != nil {
			rr.domainAggregate = aggregateDomainMatchers(rule)
		}
		if rr.needsAttributes {
			r.needsSniffingAttributes.Store(true)
		}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				closeNewWebhooks()
				return err
			}
			rr.Webhook = notifier
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				if rr.Webhook != nil {
					rr.Webhook.Close()
				}
				closeNewWebhooks()
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		r.rules = append(r.rules, rr)
	}
	r.updateDomainOnlyRuleCount()

	return nil
}

func (r *Router) RuleExists(tag string) bool {
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag == tag {
				return true
			}
		}
	}
	return false
}

// RemoveRule implements routing.Router.
func (r *Router) RemoveRule(tag string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	newRules := []*Rule{}
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag != tag {
				newRules = append(newRules, rule)
			} else if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
		r.rules = newRules
		r.updateDomainOnlyRuleCount()
		needsAttributes := false
		for _, rule := range r.rules {
			if rule.needsAttributes {
				needsAttributes = true
				break
			}
		}
		r.needsSniffingAttributes.Store(needsAttributes)
		return nil
	}
	return errors.New("empty tag name!")
}

// NeedsSniffingAttributes reports whether any active route rule consumes HTTP
// attributes. The dispatcher uses it to avoid collecting unused headers.
func (r *Router) NeedsSniffingAttributes() bool {
	return r.needsSniffingAttributes.Load()
}

// ListRule implements routing.Router
func (r *Router) ListRule() []routing.Route {
	r.mu.Lock()
	defer r.mu.Unlock()
	ruleList := make([]routing.Route, 0)
	for _, rule := range r.rules {
		ruleList = append(ruleList, &Route{
			outboundTag: rule.Tag,
			ruleTag:     rule.RuleTag,
		})
	}
	return ruleList
}

func (r *Router) pickRouteInternal(ctx routing.Context) (*Rule, routing.Context, error) {
	if r.domainStrategy == Config_IpOnDemand {
		// SkipDNSResolve is set from DNS module. The DOH remote server may be
		// a domain name, so resolving it again would create a cycle.
		if !ctx.GetSkipDNSResolve() {
			ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
		}
	}

	if rule := r.matchRule(ctx); rule != nil {
		return rule, ctx, nil
	}

	if r.domainStrategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || ctx.GetSkipDNSResolve() {
		return nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)

	// Try applying rules again if we have IPs.
	for _, rule := range r.rules {
		if !rule.needsTargetIPs {
			continue
		}
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	return nil, ctx, common.ErrNoClue
}

func (r *Router) matchRule(ctx routing.Context) *Rule {
	if r.domainOnlyRules < 2 {
		for _, rule := range r.rules {
			if rule.Apply(ctx) {
				return rule
			}
		}
		return nil
	}
	return r.matchRuleForDomain(ctx, normalizeRoutingDomain(ctx.GetTargetDomain()), false)
}

func (r *Router) matchRuleForDomain(ctx routing.Context, domain string, skipTargetIPRules bool) *Rule {
	if r.domainRuleIndex != nil {
		aggregateRule := -1
		if domain != "" {
			if index, found := r.domainRuleIndex.MatchFirst(domain); found {
				aggregateRule = int(index)
			}
		}
		for _, candidate := range r.nonAggregateRules {
			if aggregateRule >= 0 && candidate.index > aggregateRule {
				break
			}
			matched := false
			if skipTargetIPRules && candidate.rule.needsTargetIPs {
				continue
			} else if candidate.rule.domainMatcher != nil {
				matched = domain != "" && candidate.rule.domainMatcher.DomainMatcher.MatchAny(domain)
			} else {
				matched = candidate.rule.Apply(ctx)
			}
			if matched {
				return candidate.rule
			}
		}
		if aggregateRule >= 0 {
			return r.rules[aggregateRule]
		}
	} else {
		for _, rule := range r.rules {
			matched := false
			if skipTargetIPRules && rule.needsTargetIPs {
				continue
			} else if rule.domainMatcher != nil {
				matched = domain != "" && rule.domainMatcher.DomainMatcher.MatchAny(domain)
			} else {
				matched = rule.Apply(ctx)
			}
			if matched {
				return rule
			}
		}
	}
	return nil
}

func normalizeRoutingDomain(domain string) string {
	for index := range len(domain) {
		character := domain[index]
		if (character >= 'A' && character <= 'Z') || character >= 0x80 {
			return strings.ToLower(domain)
		}
	}
	return domain
}

func (r *Router) pickRouteTagIPIfNonMatch(ctx routing.Context) (*Rule, error) {
	var rule *Rule
	targetDomain := ""
	if r.domainOnlyRules >= 2 {
		targetDomain = ctx.GetTargetDomain()
		rule = r.matchRuleForDomain(ctx, normalizeRoutingDomain(targetDomain), len(ctx.GetTargetIPs()) == 0)
	} else {
		rule = r.matchRule(ctx)
	}
	if rule != nil {
		return rule, nil
	}
	if targetDomain == "" {
		targetDomain = ctx.GetTargetDomain()
	}
	if targetDomain == "" || ctx.GetSkipDNSResolve() {
		return nil, common.ErrNoClue
	}
	if r.simpleTargetIPRules {
		resolved := routing_dns.NewResolvableContext(ctx, r.dns)
		resolved.ResetWithDomain(ctx, r.dns, targetDomain)
		singleIP, hasSingleIP := resolved.GetTargetNetIPAddr()
		var ips []net.IP
		if !hasSingleIP {
			ips = resolved.GetTargetIPs()
		}
		for _, candidate := range r.rules {
			matcher := candidate.targetIPMatcher
			if matcher == nil {
				continue
			}
			matched := false
			if hasSingleIP {
				matched = matcher.matcher.MatchAddr(singleIP)
			} else {
				matched = matcher.matcher.AnyMatch(ips)
			}
			if matched {
				return candidate, nil
			}
		}
		return nil, common.ErrNoClue
	}
	resolved, _ := r.resolvableContexts.Get().(*routing_dns.ResolvableContext)
	if resolved == nil {
		resolved = new(routing_dns.ResolvableContext)
	}
	resolved.ResetWithDomain(ctx, r.dns, targetDomain)
	var matched *Rule
	for _, rule := range r.rules {
		if rule.needsTargetIPs && rule.Apply(resolved) {
			matched = rule
			break
		}
	}
	resolved.Reset(nil, nil)
	r.resolvableContexts.Put(resolved)
	if matched != nil {
		return matched, nil
	}
	return nil, common.ErrNoClue
}

func (r *Router) updateDomainOnlyRuleCount() {
	count := 0
	aggregateCount := 0
	hasTargetIPRules := false
	simpleTargetIPRules := true
	for _, rule := range r.rules {
		if rule.domainMatcher != nil {
			count++
		}
		if len(rule.domainAggregate) != 0 {
			aggregateCount++
		}
		if rule.needsTargetIPs {
			hasTargetIPRules = true
			if rule.targetIPMatcher == nil {
				simpleTargetIPRules = false
			}
		}
	}
	r.simpleTargetIPRules = hasTargetIPRules && simpleTargetIPRules
	r.domainOnlyRules = count
	r.domainRuleIndex = nil
	r.nonAggregateRules = nil
	if aggregateCount < 2 {
		return
	}
	index := strmatcher.NewMphMatcherGroup()
	for ruleIndex, rule := range r.rules {
		for _, matcher := range rule.domainAggregate {
			switch matcher := matcher.(type) {
			case strmatcher.DomainMatcher:
				index.AddDomainMatcher(matcher, uint32(ruleIndex))
			case strmatcher.FullMatcher:
				index.AddFullMatcher(matcher, uint32(ruleIndex))
			}
		}
	}
	common.Must(index.Build())
	r.domainRuleIndex = index
	for ruleIndex, rule := range r.rules {
		if len(rule.domainAggregate) == 0 {
			r.nonAggregateRules = append(r.nonAggregateRules, indexedRule{index: ruleIndex, rule: rule})
		}
	}
}

func aggregateDomainMatchers(rule *RoutingRule) []strmatcher.Matcher {
	matchers := make([]strmatcher.Matcher, 0, len(rule.GetDomain()))
	for _, domainRule := range rule.GetDomain() {
		custom := domainRule.GetCustom()
		if custom == nil {
			return nil
		}
		var matcherType strmatcher.Type
		switch custom.GetType() {
		case geodata.Domain_Domain:
			matcherType = strmatcher.Domain
		case geodata.Domain_Full:
			matcherType = strmatcher.Full
		default:
			return nil
		}
		matcher, err := matcherType.New(strings.ToLower(custom.GetValue()))
		if err != nil {
			return nil
		}
		matchers = append(matchers, matcher)
	}
	return matchers
}

func routingRuleNeedsTargetIPs(rule *RoutingRule) bool {
	return len(rule.GetIp()) != 0
}

// Start implements common.Runnable.
func (r *Router) Start() error {
	return nil
}

// closeWebhooks closes all webhook notifiers in the current rule set.
func (r *Router) closeWebhooks() {
	for _, rule := range r.rules {
		if rule.Webhook != nil {
			rule.Webhook.Close()
		}
	}
}

// Close implements common.Closable.
func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeWebhooks()
	return nil
}

// Type implements common.HasType.
func (*Router) Type() interface{} {
	return routing.RouterType()
}

// GetOutboundGroupTags implements routing.Route.
func (r *Route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

// GetOutboundTag implements routing.Route.
func (r *Route) GetOutboundTag() string {
	return r.outboundTag
}

func (r *Route) GetRuleTag() string {
	return r.ruleTag
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
			return r.Init(ctx, config.(*Config), d, ohm, dispatcher)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}
