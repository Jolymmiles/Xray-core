package router

import (
	"context"
	"fmt"
	stdnetip "net/netip"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

var routeBenchmarkSink routing.Route
var routeTagBenchmarkSink string
var ipMatcherBenchmarkSink bool

type countingSkipDNSContext struct {
	routing.Context
	calls int
}

type countingTargetDomainContext struct {
	routing.Context
	calls int
}

func (c *countingTargetDomainContext) GetTargetDomain() string {
	c.calls++
	return c.Context.GetTargetDomain()
}

func (c *countingSkipDNSContext) GetSkipDNSResolve() bool {
	c.calls++
	return c.Context.GetSkipDNSResolve()
}

type staticPerformanceDNS struct {
	ips []net.IP
}

func (*staticPerformanceDNS) Type() interface{} { return dns.ClientType() }
func (*staticPerformanceDNS) Start() error      { return nil }
func (*staticPerformanceDNS) Close() error      { return nil }
func (d *staticPerformanceDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	return d.ips, 300, nil
}

func benchmarkStaticRouter(tb testing.TB) (*Router, routing.Context) {
	tb.Helper()
	router := new(Router)
	err := router.Init(context.Background(), &Config{
		Rule: []*RoutingRule{{
			TargetTag: &RoutingRule_Tag{Tag: "DIRECT"},
			Networks:  []net.Network{net.Network_TCP},
			RuleTag:   "tcp-direct",
		}}}, nil, nil, nil)
	if err != nil {
		tb.Fatal(err)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}})
	return router, routing_session.AsRoutingContext(ctx)
}

func BenchmarkPickRouteStaticTag(b *testing.B) {
	router, ctx := benchmarkStaticRouter(b)
	b.ReportAllocs()
	for b.Loop() {
		route, err := router.PickRoute(ctx)
		if err != nil {
			b.Fatal(err)
		}
		routeBenchmarkSink = route
	}
}

func BenchmarkPickRouteTagStaticTag(b *testing.B) {
	router, ctx := benchmarkStaticRouter(b)
	b.ReportAllocs()
	for b.Loop() {
		outboundTag, ruleTag, err := router.PickRouteTag(ctx)
		if err != nil {
			b.Fatal(err)
		}
		routeTagBenchmarkSink = outboundTag
		routeTagBenchmarkSink = ruleTag
	}
}

func BenchmarkPickRouteTagFromSessionContextLegacy(b *testing.B) {
	router, _ := benchmarkStaticRouter(b)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}})
	b.ReportAllocs()
	for b.Loop() {
		routingContext := routing_session.AsRoutingContext(ctx)
		outboundTag, ruleTag, err := router.PickRouteTag(routingContext)
		if err != nil {
			b.Fatal(err)
		}
		routeTagBenchmarkSink = outboundTag
		routeTagBenchmarkSink = ruleTag
	}
}

func BenchmarkPickRouteTagFromConnectionContext(b *testing.B) {
	router, _ := benchmarkStaticRouter(b)
	ctx := session.ContextWithConnection(
		context.Background(),
		42,
		session.Inbound{Tag: "vless-in"},
		session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 443)},
		session.Content{},
	)
	ctx = context.WithValue(ctx, struct{ name string }{"protocol-wrapper"}, true)
	b.ReportAllocs()
	for b.Loop() {
		routingContext := routing_session.AsRoutingContext(ctx)
		outboundTag, ruleTag, err := router.PickRouteTag(routingContext)
		if err != nil {
			b.Fatal(err)
		}
		routeTagBenchmarkSink = outboundTag
		routeTagBenchmarkSink = ruleTag
	}
}

func BenchmarkPickRouteTagIPIfNonMatch(b *testing.B) {
	rules := make([]*RoutingRule, 0, 9)
	for index := range 8 {
		domainRules, err := geodata.ParseDomainRules([]string{
			"miss-" + string(rune('a'+index)) + ".example",
		}, geodata.Domain_Domain)
		if err != nil {
			b.Fatal(err)
		}
		rules = append(rules, &RoutingRule{
			TargetTag: &RoutingRule_Tag{Tag: "DOMAIN-MISS"},
			Domain:    domainRules,
		})
	}
	ipRules, err := geodata.ParseIPRules([]string{"192.0.2.1/32"})
	if err != nil {
		b.Fatal(err)
	}
	rules = append(rules, &RoutingRule{
		TargetTag: &RoutingRule_Tag{Tag: "DIRECT"},
		Ip:        ipRules,
	})

	router := new(Router)
	err = router.Init(context.Background(), &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule:           rules,
	}, &staticPerformanceDNS{ips: []net.IP{{192, 0, 2, 1}}}, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}})
	routingContext := routing_session.AsRoutingContext(ctx)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		outboundTag, ruleTag, err := router.PickRouteTag(routingContext)
		if err != nil {
			b.Fatal(err)
		}
		routeTagBenchmarkSink = outboundTag
		routeTagBenchmarkSink = ruleTag
	}
}

func TestPickRouteTagIPIfNonMatchAllocationBudget(t *testing.T) {
	domainRules, err := geodata.ParseDomainRules([]string{"miss.example", "other.example"}, geodata.Domain_Domain)
	if err != nil {
		t.Fatal(err)
	}
	ipRules, err := geodata.ParseIPRules([]string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	router := new(Router)
	if err := router.Init(context.Background(), &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{
			{TargetTag: &RoutingRule_Tag{Tag: "MISS"}, Domain: domainRules[:1]},
			{TargetTag: &RoutingRule_Tag{Tag: "MISS"}, Domain: domainRules[1:]},
			{TargetTag: &RoutingRule_Tag{Tag: "DIRECT"}, Ip: ipRules},
		},
	}, &staticPerformanceDNS{ips: []net.IP{{192, 0, 2, 1}}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := &routing_session.Context{Outbound: &session.Outbound{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}}
	allocations := testing.AllocsPerRun(1000, func() {
		if _, _, err := router.PickRouteTag(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("PickRouteTag IPIfNonMatch allocations = %.0f, want 0", allocations)
	}
	counting := &countingTargetDomainContext{Context: ctx}
	if _, _, err := router.PickRouteTag(counting); err != nil {
		t.Fatal(err)
	}
	if counting.calls != 1 {
		t.Fatalf("IPIfNonMatch GetTargetDomain calls = %d, want 1", counting.calls)
	}
}

func TestResolvableContextExposesOnlySingleResolvedTargetAddress(t *testing.T) {
	base := &routing_session.Context{Outbound: &session.Outbound{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}}
	for _, test := range []struct {
		name string
		ips  []net.IP
		want bool
	}{
		{"single", []net.IP{{192, 0, 2, 1}}, true},
		{"multiple", []net.IP{{192, 0, 2, 1}, {192, 0, 2, 2}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved := routing_dns.NewResolvableContext(base, &staticPerformanceDNS{ips: test.ips})
			provider, ok := any(&resolved).(interface{ GetTargetNetIPAddr() (stdnetip.Addr, bool) })
			if !ok {
				t.Fatal("resolvable context does not expose a target IP")
			}
			_, got := provider.GetTargetNetIPAddr()
			if got != test.want {
				t.Fatalf("single resolved target available = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSessionRoutingContextExposesTargetNetIP(t *testing.T) {
	ctx := &routing_session.Context{Outbound: &session.Outbound{
		Target: net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443),
	}}
	ip, ok := ctx.GetTargetNetIPAddr()
	if !ok || ip.String() != "192.0.2.1" {
		t.Fatalf("target netip = %v, %t", ip, ok)
	}
	ctx.Outbound.Target = net.TCPDestination(net.DomainAddress("example.com"), 443)
	if _, ok := ctx.GetTargetNetIPAddr(); ok {
		t.Fatal("domain target unexpectedly exposed as netip")
	}
}

func TestPickRouteTagIPIfNonMatchMatchesAnyResolvedIP(t *testing.T) {
	ipRules, err := geodata.ParseIPRules([]string{"192.0.2.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	router := new(Router)
	if err := router.Init(context.Background(), &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{{
			TargetTag: &RoutingRule_Tag{Tag: "DIRECT"},
			Ip:        ipRules,
		}},
	}, &staticPerformanceDNS{ips: []net.IP{{192, 0, 2, 1}, {192, 0, 2, 2}}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := &routing_session.Context{Outbound: &session.Outbound{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}}
	tag, _, err := router.PickRouteTag(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "DIRECT" {
		t.Fatalf("outbound tag = %q, want DIRECT", tag)
	}
}

func TestIPIfNonMatchPreservesAvailableTargetIPRuleOrder(t *testing.T) {
	ipRules, err := geodata.ParseIPRules([]string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	domainRule := func(tag, domain string) *RoutingRule {
		return &RoutingRule{
			TargetTag: &RoutingRule_Tag{Tag: tag},
			Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{
				Type: geodata.Domain_Domain, Value: domain,
			}}}},
		}
	}
	router := new(Router)
	if err := router.Init(context.Background(), &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{
			{TargetTag: &RoutingRule_Tag{Tag: "IP-FIRST"}, Ip: ipRules},
			domainRule("DOMAIN", "match.example"),
			domainRule("OTHER", "other.example"),
		},
	}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := &routing_session.Context{Outbound: &session.Outbound{
		Target:      net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443),
		RouteTarget: net.TCPDestination(net.DomainAddress("www.match.example"), 443),
	}}
	tag, _, err := router.PickRouteTag(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "IP-FIRST" {
		t.Fatalf("outbound tag = %q, want IP-FIRST", tag)
	}
}

func BenchmarkPickRouteTagDomainRules(b *testing.B) {
	benchmarkPickRouteTagDomainRules(b, "www.domainh.example")
}

func BenchmarkPickRouteTagDomainRulesFirst(b *testing.B) {
	benchmarkPickRouteTagDomainRules(b, "www.domaina.example")
}

func benchmarkPickRouteTagDomainRules(b *testing.B, target string) {
	rules := make([]*RoutingRule, 0, 8)
	for index := range 8 {
		rules = append(rules, &RoutingRule{
			TargetTag: &RoutingRule_Tag{Tag: "OUT"},
			Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{
				Type: geodata.Domain_Domain, Value: "domain" + string(rune('a'+index)) + ".example",
			}}}},
		})
	}
	router := new(Router)
	if err := router.Init(context.Background(), &Config{Rule: rules, DomainStrategy: Config_IpIfNonMatch}, nil, nil, nil); err != nil {
		b.Fatal(err)
	}
	ctx := session.ContextWithConnection(
		context.Background(), 42, session.Inbound{Tag: "vless-in"},
		session.Outbound{Target: net.TCPDestination(net.DomainAddress(target), 443)},
		session.Content{},
	)
	routingContext := session.RoutingContextFromContext(ctx)
	b.ReportAllocs()
	for b.Loop() {
		outboundTag, _, err := router.PickRouteTag(routingContext)
		if err != nil {
			b.Fatal(err)
		}
		routeTagBenchmarkSink = outboundTag
	}
}

func TestDomainOnlyRulesReadAndNormalizeDomainOnce(t *testing.T) {
	rules := []*RoutingRule{
		{
			TargetTag: &RoutingRule_Tag{Tag: "FIRST"},
			Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{
				Type: geodata.Domain_Domain, Value: "first.example",
			}}}},
		},
		{
			TargetTag: &RoutingRule_Tag{Tag: "SECOND"},
			Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{
				Type: geodata.Domain_Domain, Value: "second.example",
			}}}},
		},
	}
	router := new(Router)
	if err := router.Init(context.Background(), &Config{Rule: rules}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	base := &routing_session.Context{Outbound: &session.Outbound{
		Target: net.TCPDestination(net.DomainAddress("WWW.SECOND.EXAMPLE"), 443),
	}}
	countingContext := &countingTargetDomainContext{Context: base}
	outboundTag, _, err := router.PickRouteTag(countingContext)
	if err != nil {
		t.Fatal(err)
	}
	if outboundTag != "SECOND" {
		t.Fatalf("outbound tag = %q, want SECOND", outboundTag)
	}
	if countingContext.calls != 1 {
		t.Fatalf("GetTargetDomain called %d times, want 1", countingContext.calls)
	}
}

func TestNormalizeRoutingDomain(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"example.com", "example.com"},
		{"WWW.EXAMPLE.COM", "www.example.com"},
		{"BÜCHER.EXAMPLE", "bücher.example"},
		{"", ""},
	} {
		if got := normalizeRoutingDomain(test.input); got != test.want {
			t.Fatalf("normalizeRoutingDomain(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestAggregateDomainRulesPreserveMixedRuleOrder(t *testing.T) {
	domainRule := func(tag, domain string) *RoutingRule {
		return &RoutingRule{
			TargetTag: &RoutingRule_Tag{Tag: tag},
			Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{
				Type: geodata.Domain_Domain, Value: domain,
			}}}},
		}
	}
	inboundRule := &RoutingRule{
		TargetTag:  &RoutingRule_Tag{Tag: "INBOUND"},
		InboundTag: []string{"vless-in"},
	}
	ctx := &routing_session.Context{
		Inbound:  &session.Inbound{Tag: "vless-in"},
		Outbound: &session.Outbound{Target: net.TCPDestination(net.DomainAddress("www.match.example"), 443)},
	}

	for _, test := range []struct {
		name  string
		rules []*RoutingRule
		want  string
	}{
		{name: "non-domain first", rules: []*RoutingRule{inboundRule, domainRule("DOMAIN", "match.example"), domainRule("OTHER", "other.example")}, want: "INBOUND"},
		{name: "domain first", rules: []*RoutingRule{domainRule("DOMAIN", "match.example"), inboundRule, domainRule("OTHER", "other.example")}, want: "DOMAIN"},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := new(Router)
			if err := router.Init(context.Background(), &Config{Rule: test.rules}, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			outboundTag, _, err := router.PickRouteTag(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if outboundTag != test.want {
				t.Fatalf("outbound tag = %q, want %q", outboundTag, test.want)
			}
		})
	}
}

func BenchmarkTargetIPMatcherDirectIP(b *testing.B) {
	rules, err := geodata.ParseIPRules([]string{"192.0.2.1/32"})
	if err != nil {
		b.Fatal(err)
	}
	matcher, err := NewIPMatcher(rules, MatcherAsType_Target)
	if err != nil {
		b.Fatal(err)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443),
	}})
	routingContext := routing_session.AsRoutingContext(ctx)

	b.ReportAllocs()
	for b.Loop() {
		ipMatcherBenchmarkSink = matcher.Apply(routingContext)
	}
}

func BenchmarkTargetIPMatcherDirectIPManyCIDRs(b *testing.B) {
	rawRules := make([]string, 64)
	for index := range rawRules {
		rawRules[index] = fmt.Sprintf("192.0.2.%d/32", index)
	}
	rules, err := geodata.ParseIPRules(rawRules)
	if err != nil {
		b.Fatal(err)
	}
	matcher, err := NewIPMatcher(rules, MatcherAsType_Target)
	if err != nil {
		b.Fatal(err)
	}
	ctx := &routing_session.Context{Outbound: &session.Outbound{
		Target: net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 63}), 443),
	}}
	b.ReportAllocs()
	for b.Loop() {
		ipMatcherBenchmarkSink = matcher.Apply(ctx)
	}
}

func TestExactIPMatcherPreservesReverseAndAddressFamily(t *testing.T) {
	rules, err := geodata.ParseIPRules([]string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := geodata.IPReg.BuildIPMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	matched := stdnetip.MustParseAddr("192.0.2.1")
	unmatched := stdnetip.MustParseAddr("192.0.2.2")
	ipv6 := stdnetip.MustParseAddr("2001:db8::1")
	if !matcher.MatchAddr(matched) || matcher.MatchAddr(unmatched) || matcher.MatchAddr(ipv6) {
		t.Fatal("positive exact matcher returned an unexpected result")
	}
	matcher.SetReverse(true)
	if matcher.MatchAddr(matched) || !matcher.MatchAddr(unmatched) || matcher.MatchAddr(ipv6) {
		t.Fatal("reversed exact matcher returned an unexpected result")
	}
}

func TestPickRouteTagMatchesPickRoute(t *testing.T) {
	router, ctx := benchmarkStaticRouter(t)
	route, err := router.PickRoute(ctx)
	if err != nil {
		t.Fatal(err)
	}
	outboundTag, ruleTag, err := router.PickRouteTag(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if outboundTag != route.GetOutboundTag() || ruleTag != route.GetRuleTag() {
		t.Fatalf("PickRouteTag() = (%q, %q), want (%q, %q)", outboundTag, ruleTag, route.GetOutboundTag(), route.GetRuleTag())
	}
}

func TestRoutingRuleNeedsTargetIPs(t *testing.T) {
	tests := []struct {
		name string
		rule *RoutingRule
		want bool
	}{
		{"domain only", &RoutingRule{Domain: []*geodata.DomainRule{{}}}, false},
		{"target IP", &RoutingRule{Ip: []*geodata.IPRule{{}}}, true},
		{"source IP", &RoutingRule{SourceIp: []*geodata.IPRule{{}}}, false},
		{"local IP", &RoutingRule{LocalIp: []*geodata.IPRule{{}}}, false},
		{"domain and target IP", &RoutingRule{Domain: []*geodata.DomainRule{{}}, Ip: []*geodata.IPRule{{}}}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := routingRuleNeedsTargetIPs(test.rule); got != test.want {
				t.Fatalf("routingRuleNeedsTargetIPs() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRouterNeedsSniffingAttributesLifecycle(t *testing.T) {
	router := new(Router)
	if err := router.Init(context.Background(), &Config{Rule: []*RoutingRule{{
		TargetTag: &RoutingRule_Tag{Tag: "DIRECT"},
		RuleTag:   "domain-only",
		Networks:  []net.Network{net.Network_TCP},
	}}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if router.NeedsSniffingAttributes() {
		t.Fatal("router without attribute rules requested HTTP attributes")
	}

	if err := router.ReloadRules(&Config{Rule: []*RoutingRule{{
		TargetTag: &RoutingRule_Tag{Tag: "DIRECT"},
		RuleTag:   "attribute-rule",
		Attributes: map[string]string{
			"user-agent": "benchmark",
		},
	}}}, true); err != nil {
		t.Fatal(err)
	}
	if !router.NeedsSniffingAttributes() {
		t.Fatal("router with attribute rule did not request HTTP attributes")
	}

	if err := router.RemoveRule("attribute-rule"); err != nil {
		t.Fatal(err)
	}
	if router.NeedsSniffingAttributes() {
		t.Fatal("router retained attribute requirement after rule removal")
	}
}

func TestBenchmarkStaticRouterMatches(t *testing.T) {
	router := new(Router)
	common.Must(router.Init(context.Background(), &Config{
		Rule: []*RoutingRule{{
			TargetTag: &RoutingRule_Tag{Tag: "DIRECT"},
			Networks:  []net.Network{net.Network_TCP},
		}}}, nil, nil, nil))
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}})
	if _, err := router.PickRoute(routing_session.AsRoutingContext(ctx)); err != nil {
		t.Fatal(err)
	}
}

func TestSingleConditionBuildMatches(t *testing.T) {
	condition, err := (&RoutingRule{Networks: []net.Network{net.Network_TCP}}).BuildCondition()
	if err != nil {
		t.Fatal(err)
	}
	tcpContext := &routing_session.Context{Outbound: &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 443)}}
	udpContext := &routing_session.Context{Outbound: &session.Outbound{Target: net.UDPDestination(net.DomainAddress("example.com"), 443)}}
	if !condition.Apply(tcpContext) {
		t.Fatal("single TCP condition did not match TCP context")
	}
	if condition.Apply(udpContext) {
		t.Fatal("single TCP condition matched UDP context")
	}
}

func TestMatchingRuleDoesNotReadSkipDNSResolve(t *testing.T) {
	router, routingContext := benchmarkStaticRouter(t)
	countingContext := &countingSkipDNSContext{Context: routingContext}
	if _, _, err := router.PickRouteTag(countingContext); err != nil {
		t.Fatal(err)
	}
	if countingContext.calls != 0 {
		t.Fatalf("GetSkipDNSResolve called %d times, want 0 for an immediately matching rule", countingContext.calls)
	}
}
