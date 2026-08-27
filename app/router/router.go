package router

import (
	"context"
	"maps"
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
	rules               atomic.Pointer[[]*Rule]
	domainOnlyRules     int
	domainRuleIndex     *strmatcher.MphMatcherGroup
	nonAggregateRules   []indexedRule
	simpleTargetIPRules bool
	balancers           atomic.Pointer[map[string]*Balancer]
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

func (r *Router) currentRules() []*Rule {
	if pointer := r.rules.Load(); pointer != nil {
		return *pointer
	}
	return nil
}

func (r *Router) currentBalancers() map[string]*Balancer {
	if pointer := r.balancers.Load(); pointer != nil {
		return *pointer
	}
	return map[string]*Balancer{}
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	r.domainStrategy = config.DomainStrategy
	r.dns = d
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher
	r.needsSniffingAttributes.Store(false)
	r.rules.Store(new([]*Rule))
	r.balancers.Store(&map[string]*Balancer{})
	return r.ReloadRules(config, false)
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

	oldRules := r.currentRules()
	oldBalancers := r.currentBalancers()

	var newRules []*Rule
	newBalancers := make(map[string]*Balancer)
	existTags := make(map[string]bool, len(oldRules)+len(config.Rule))
	kept := 0
	if shouldAppend {
		newRules = append(newRules, oldRules...)
		maps.Copy(newBalancers, oldBalancers)
		kept = len(newRules)
		for _, rule := range oldRules {
			existTags[rule.RuleTag] = true
		}
	}

	closeCreated := func() {
		closeWebhooks(newRules[kept:])
	}

	for _, rule := range config.BalancingRule {
		if _, found := newBalancers[rule.Tag]; found {
			closeCreated()
			return errors.New("duplicate balancer tag")
		}
		balancer, err := rule.Build(r.ohm, r.dispatcher)
		if err != nil {
			closeCreated()
			return err
		}
		balancer.InjectContext(r.ctx)
		newBalancers[rule.Tag] = balancer
	}

	for _, rule := range config.Rule {
		if rule.GetRuleTag() != "" && existTags[rule.GetRuleTag()] {
			closeCreated()
			return errors.New("duplicate ruleTag ", rule.GetRuleTag())
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			closeCreated()
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
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				closeCreated()
				return err
			}
			rr.Webhook = notifier
		}
		if btag := rule.GetBalancingTag(); len(btag) > 0 {
			brule, found := newBalancers[btag]
			if !found {
				if rr.Webhook != nil {
					rr.Webhook.Close()
				}
				closeCreated()
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		existTags[rr.RuleTag] = true
		newRules = append(newRules, rr)
	}

	r.publishRoutingTable(newRules, newBalancers)
	if !shouldAppend {
		closeWebhooks(oldRules)
	}
	return nil
}

func (r *Router) publishRoutingTable(rules []*Rule, balancers map[string]*Balancer) {
	r.updateDomainOnlyRuleCount(rules)
	needsAttributes := false
	for _, rule := range rules {
		if rule.needsAttributes {
			needsAttributes = true
			break
		}
	}
	r.needsSniffingAttributes.Store(needsAttributes)
	r.balancers.Store(&balancers)
	r.rules.Store(&rules)
}

func (r *Router) RuleExists(tag string) bool {
	if tag == "" {
		return false
	}
	for _, rule := range r.currentRules() {
		if rule.RuleTag == tag {
			return true
		}
	}
	return false
}

// RemoveRule implements routing.Router.
func (r *Router) RemoveRule(tag string) error {
	if tag == "" {
		return errors.New("empty tag name!")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	oldRules := r.currentRules()
	newRules := make([]*Rule, 0, len(oldRules))
	var removed []*Rule
	for _, rule := range oldRules {
		if rule.RuleTag != tag {
			newRules = append(newRules, rule)
		} else {
			removed = append(removed, rule)
		}
	}
	r.publishRoutingTable(newRules, r.currentBalancers())
	closeWebhooks(removed)
	return nil
}

// NeedsSniffingAttributes reports whether any active route rule consumes HTTP
// attributes. The dispatcher uses it to avoid collecting unused headers.
func (r *Router) NeedsSniffingAttributes() bool {
	return r.needsSniffingAttributes.Load()
}

// ListRule implements routing.Router
func (r *Router) ListRule() []routing.Route {
	rules := r.currentRules()
	ruleList := make([]routing.Route, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, &Route{
			outboundTag: rule.Tag,
			ruleTag:     rule.RuleTag,
		})
	}
	return ruleList
}

func (r *Router) pickRouteInternal(ctx routing.Context) (*Rule, routing.Context, error) {
	rules := r.currentRules()
	if r.domainStrategy == Config_IpOnDemand {
		// SkipDNSResolve is set from DNS module. The DOH remote server may be
		// a domain name, so resolving it again would create a cycle.
		if !ctx.GetSkipDNSResolve() {
			ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
		}
	}

	if rule := r.matchRule(ctx, rules); rule != nil {
		return rule, ctx, nil
	}

	if r.domainStrategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || ctx.GetSkipDNSResolve() {
		return nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)

	// Try applying rules again if we have IPs.
	for _, rule := range rules {
		if !rule.needsTargetIPs {
			continue
		}
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	return nil, ctx, common.ErrNoClue
}

func (r *Router) matchRule(ctx routing.Context, rules []*Rule) *Rule {
	if r.domainOnlyRules < 2 {
		for _, rule := range rules {
			if rule.Apply(ctx) {
				return rule
			}
		}
		return nil
	}
	return r.matchRuleForDomain(ctx, rules, normalizeRoutingDomain(ctx.GetTargetDomain()), false)
}

func (r *Router) matchRuleForDomain(ctx routing.Context, rules []*Rule, domain string, skipTargetIPRules bool) *Rule {
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
		if aggregateRule >= 0 && aggregateRule < len(rules) {
			return rules[aggregateRule]
		}
	} else {
		for _, rule := range rules {
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
	rules := r.currentRules()
	var rule *Rule
	targetDomain := ""
	if r.domainOnlyRules >= 2 {
		targetDomain = ctx.GetTargetDomain()
		rule = r.matchRuleForDomain(ctx, rules, normalizeRoutingDomain(targetDomain), len(ctx.GetTargetIPs()) == 0)
	} else {
		rule = r.matchRule(ctx, rules)
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
		for _, candidate := range rules {
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
	for _, rule := range rules {
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

func (r *Router) updateDomainOnlyRuleCount(rules []*Rule) {
	count := 0
	aggregateCount := 0
	hasTargetIPRules := false
	simpleTargetIPRules := true
	for _, rule := range rules {
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
	for ruleIndex, rule := range rules {
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
	for ruleIndex, rule := range rules {
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

// closeWebhooks closes all webhook notifiers in the given rule set.
func closeWebhooks(rules []*Rule) {
	for _, rule := range rules {
		if rule.Webhook != nil {
			rule.Webhook.Close()
		}
	}
}

// Close implements common.Closable.
func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	closeWebhooks(r.currentRules())
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
