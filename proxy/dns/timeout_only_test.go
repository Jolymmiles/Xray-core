package dns_test

import (
	"context"
	go_errors "errors"
	gonet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	dns_proxy "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

const (
	timeoutOnlyInboundTag = "dns-module"
	timeoutOnlySessionID  = xctx.ID(4242)
	upstreamAnswer        = "192.0.2.1"
)

// timeoutOnlyPolicy gives the DNS outbound a chosen idle timeout.
type timeoutOnlyPolicy struct {
	idle time.Duration
}

func (*timeoutOnlyPolicy) Type() interface{} { return policy.ManagerType() }
func (*timeoutOnlyPolicy) Start() error      { return nil }
func (*timeoutOnlyPolicy) Close() error      { return nil }

func (p *timeoutOnlyPolicy) ForLevel(uint32) policy.Session {
	s := policy.SessionDefault()
	s.Timeouts.ConnectionIdle = p.idle
	return s
}

func (*timeoutOnlyPolicy) ForSystem() policy.System { return policy.System{} }

// ownLinkClient treats sessions from timeoutOnlyInboundTag as the DNS
// module's own queries, like app/dns does for its configured tag.
type ownLinkClient struct {
	lookups atomic.Int32
}

func (*ownLinkClient) Type() interface{} { return featuredns.ClientType() }
func (*ownLinkClient) Start() error      { return nil }
func (*ownLinkClient) Close() error      { return nil }

func (c *ownLinkClient) LookupIP(string, featuredns.IPOption) ([]net.IP, uint32, error) {
	c.lookups.Add(1)
	return nil, 0, featuredns.ErrEmptyResponse
}

func (*ownLinkClient) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	return inbound != nil && inbound.Tag == timeoutOnlyInboundTag
}

// recordingDialer dials the upstream directly and keeps the context of
// every dial the DNS outbound makes. Like the system dialer, it fails when
// that context is already canceled.
type recordingDialer struct {
	mu   sync.Mutex
	ctxs []context.Context
}

func (d *recordingDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	d.mu.Lock()
	d.ctxs = append(d.ctxs, ctx)
	d.mu.Unlock()
	return (&gonet.Dialer{}).DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}

func (*recordingDialer) DestIpAddress() net.IP { return nil }

func (*recordingDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func (d *recordingDialer) dials() []context.Context {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]context.Context(nil), d.ctxs...)
}

func startUpstreamDNS(t *testing.T) net.Destination {
	t.Helper()
	pc, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ans := new(dns.Msg)
			ans.SetReply(r)
			for _, q := range r.Question {
				if q.Qtype == dns.TypeA {
					rr, err := dns.NewRR(q.Name + " IN A " + upstreamAnswer)
					if err != nil {
						panic(err)
					}
					ans.Answer = append(ans.Answer, rr)
				}
			}
			_ = w.WriteMsg(ans)
		}),
		NotifyStartedFunc: func() { close(started) },
	}
	served := make(chan struct{})
	var serveErr error
	go func() {
		serveErr = server.ActivateAndServe()
		close(served)
	}()
	// Join the serve goroutine on every path. Closing the socket releases it
	// even when the server never started.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := server.ShutdownContext(ctx)
		_ = pc.Close()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("upstream DNS server did not stop within 5s")
			return
		}
		select {
		case <-started:
			if shutdownErr != nil {
				t.Errorf("shut down upstream DNS server: %v", shutdownErr)
			}
			if serveErr != nil {
				t.Errorf("upstream DNS server: %v", serveErr)
			}
		default:
		}
	})
	select {
	case <-started:
	case <-served:
		t.Fatalf("upstream DNS server stopped before serving: %v", serveErr)
	case <-time.After(10 * time.Second):
		t.Fatal("upstream DNS server did not start within 10s")
	}
	return net.DestinationFromAddr(pc.LocalAddr())
}

// timeoutOnlySession is one DNS outbound Process call driven through pipes,
// with the session values an XUDP flow carries.
type timeoutOnlySession struct {
	uplink   *pipe.Writer
	downlink *pipe.Reader
	dialer   *recordingDialer
	client   *ownLinkClient
	outbound *session.Outbound
	done     chan error
}

func startTimeoutOnlySession(t *testing.T, parent context.Context, config *dns_proxy.Config, idle time.Duration) *timeoutOnlySession {
	t.Helper()
	upstream := startUpstreamDNS(t)

	s := &timeoutOnlySession{
		dialer: &recordingDialer{},
		client: &ownLinkClient{},
		done:   make(chan error, 1),
	}
	handler := new(dns_proxy.Handler)
	if err := handler.Init(config, s.client, &timeoutOnlyPolicy{idle: idle}); err != nil {
		t.Fatal(err)
	}

	ctx := session.ContextWithConnection(parent, timeoutOnlySessionID,
		session.Inbound{
			Tag:    timeoutOnlyInboundTag,
			Name:   "vless",
			Source: net.UDPDestination(net.LocalHostIP, 5353),
		},
		session.Outbound{Target: upstream, Tag: "dns-out"},
		session.Content{Protocol: "dns"},
	)
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	s.outbound = session.OutboundsFromContext(ctx)[0]

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	s.uplink = uplinkWriter
	s.downlink = downlinkReader
	link := &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}
	go func() { s.done <- handler.Process(ctx, link, s.dialer) }()
	// Interrupting both pipes releases Process and its copy goroutines on
	// every exit path, as the outbound handler does after Process returns.
	t.Cleanup(func() {
		uplinkWriter.Close()
		uplinkReader.Interrupt()
		downlinkWriter.Close()
		downlinkReader.Interrupt()
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
			t.Error("DNS outbound did not stop within 10s after its link closed")
		}
	})
	return s
}

// exchange sends one A query through the session and returns the answer.
func (s *timeoutOnlySession) exchange(t *testing.T, id uint16, domain string) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	query.Id = id
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	b := buf.New()
	if _, err := b.Write(packed); err != nil {
		t.Fatal(err)
	}
	if err := s.uplink.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("write query %d: %v", id, err)
	}

	mb, err := s.downlink.ReadMultiBufferTimeout(10 * time.Second)
	if err != nil {
		t.Fatalf("no answer to query %d within 10s: %v", id, err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 {
		t.Fatalf("answer to query %d arrived in %d buffers, want 1", id, len(mb))
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(mb[0].Bytes()); err != nil {
		t.Fatalf("unpack answer to query %d: %v", id, err)
	}
	if answer.Id != id {
		t.Fatalf("answer ID = %d, want %d", answer.Id, id)
	}
	return answer
}

func answeredByUpstream(m *dns.Msg) bool {
	if len(m.Answer) != 1 {
		return false
	}
	a, ok := m.Answer[0].(*dns.A)
	return ok && a.A.String() == upstreamAnswer
}

func directAll() *dns_proxy.Config {
	return &dns_proxy.Config{Rule: []*dns_proxy.DNSRuleConfig{{Action: dns_proxy.RuleAction_Direct}}}
}

func TestTimeoutOnlySessionDialsWithSessionValues(t *testing.T) {
	s := startTimeoutOnlySession(t, context.Background(), directAll(), time.Minute)

	if answer := s.exchange(t, 1, "example.com"); !answeredByUpstream(answer) {
		t.Fatalf("direct query was not answered by the upstream: %v", answer)
	}

	dials := s.dialer.dials()
	if len(dials) != 1 {
		t.Fatalf("DNS outbound dialed %d times, want 1", len(dials))
	}
	dialCtx := dials[0]
	if id := xctx.IDFromContext(dialCtx); id != timeoutOnlySessionID {
		t.Errorf("dial session ID = %d, want %d", id, timeoutOnlySessionID)
	}
	if inbound := session.InboundFromContext(dialCtx); inbound == nil || inbound.Tag != timeoutOnlyInboundTag {
		t.Errorf("dial inbound = %+v, want tag %q", inbound, timeoutOnlyInboundTag)
	}
	// The dialer reads the last outbound, for example to apply sendThrough.
	if outbounds := session.OutboundsFromContext(dialCtx); len(outbounds) != 1 || outbounds[0] != s.outbound {
		t.Errorf("dial outbounds = %v, want the session outbound %p", outbounds, s.outbound)
	}
	if content := session.ContentFromContext(dialCtx); content == nil || content.Protocol != "dns" {
		t.Errorf("dial content = %+v, want protocol dns", content)
	}
	if routing := session.RoutingContextFromContext(dialCtx); routing == nil || routing.GetInboundTag() != timeoutOnlyInboundTag {
		t.Errorf("dial routing context = %v, want inbound tag %q", routing, timeoutOnlyInboundTag)
	}
	if !session.TimeoutOnlyFromContext(dialCtx) {
		t.Error("dial context lost the timeout-only mark")
	}
}

func TestTimeoutOnlySessionRecognizesOwnLink(t *testing.T) {
	// No rules: an A query from another link is hijacked to the DNS client.
	s := startTimeoutOnlySession(t, context.Background(), &dns_proxy.Config{}, time.Minute)

	if answer := s.exchange(t, 2, "example.com"); !answeredByUpstream(answer) {
		t.Errorf("own-link query was not passed to the upstream: %v", answer)
	}
	if n := s.client.lookups.Load(); n != 0 {
		t.Errorf("own-link query was hijacked to the DNS client %d times", n)
	}
}

func TestTimeoutOnlySessionOutlivesParentCancel(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	s := startTimeoutOnlySession(t, parent, directAll(), time.Minute)

	if answer := s.exchange(t, 3, "example.com"); !answeredByUpstream(answer) {
		t.Fatalf("query before parent cancel was not answered by the upstream: %v", answer)
	}
	dials := s.dialer.dials()
	if len(dials) != 1 {
		t.Fatalf("DNS outbound dialed %d times, want 1", len(dials))
	}
	dialCtx := dials[0]

	// Cancellation propagates synchronously, so a session tied to the parent
	// is already canceled here.
	cancelParent()
	if err := dialCtx.Err(); err != nil {
		t.Fatalf("parent cancel reached the timeout-only session: %v", err)
	}

	if answer := s.exchange(t, 4, "example.org"); !answeredByUpstream(answer) {
		t.Fatalf("query after parent cancel was not answered by the upstream: %v", answer)
	}
	if n := len(s.dialer.dials()); n != 1 {
		t.Fatalf("DNS outbound dialed %d times, want the first connection reused", n)
	}
	select {
	case err := <-s.done:
		t.Fatalf("DNS outbound returned while its link was open: %v", err)
	default:
	}

	// The session still ends with its own link.
	s.uplink.Close()
	select {
	case err := <-s.done:
		s.done <- err
		if err != nil && !go_errors.Is(errors.Cause(err), context.Canceled) {
			t.Fatalf("DNS outbound ended with %v after its uplink closed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DNS outbound did not return within 10s after its uplink closed")
	}
	if dialCtx.Err() == nil {
		t.Error("DNS outbound returned without canceling its own context")
	}
}

func TestTimeoutOnlySessionDialsAfterParentCancel(t *testing.T) {
	// The DNS outbound dials on its first forwarded query, which can come
	// after the flow's originator is gone.
	parent, cancelParent := context.WithCancel(context.Background())
	s := startTimeoutOnlySession(t, parent, directAll(), time.Minute)
	cancelParent()

	if answer := s.exchange(t, 5, "example.com"); !answeredByUpstream(answer) {
		t.Fatalf("first query after parent cancel was not answered by the upstream: %v", answer)
	}
	dials := s.dialer.dials()
	if len(dials) != 1 {
		t.Fatalf("DNS outbound dialed %d times, want 1", len(dials))
	}
	if outbounds := session.OutboundsFromContext(dials[0]); len(outbounds) != 1 || outbounds[0] != s.outbound {
		t.Errorf("dial outbounds after parent cancel = %v, want the session outbound %p", outbounds, s.outbound)
	}
}

func TestTimeoutOnlySessionEndsOnItsIdleTimeout(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	s := startTimeoutOnlySession(t, parent, directAll(), 100*time.Millisecond)
	cancelParent()

	select {
	case err := <-s.done:
		s.done <- err
		if !go_errors.Is(errors.Cause(err), context.Canceled) {
			t.Fatalf("DNS outbound ended with %v, want its idle timer's cancel", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DNS outbound outlived its 100ms idle timeout by 10s")
	}
}
