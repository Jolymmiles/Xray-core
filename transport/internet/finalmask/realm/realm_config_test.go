package realm

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestIPModeFiltersCandidates(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.1:1000")
	mapped4 := netip.MustParseAddrPort("[::ffff:192.0.2.2]:1001")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:1002")
	all := []netip.AddrPort{v4, mapped4, v6}

	for _, tt := range []struct {
		name   string
		family Family
		want   []netip.AddrPort
	}{
		{name: "dual", family: Family_Dual, want: []netip.AddrPort{v4, netip.MustParseAddrPort("192.0.2.2:1001"), v6}},
		{name: "v4", family: Family_V4, want: []netip.AddrPort{v4, netip.MustParseAddrPort("192.0.2.2:1001")}},
		{name: "v6", family: Family_V6, want: []netip.AddrPort{v6}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := filterAddrPorts(all, tt.family)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInsertAddrSortsAndDeduplicates(t *testing.T) {
	one := netip.MustParseAddrPort("192.0.2.1:1")
	two := netip.MustParseAddrPort("192.0.2.2:2")
	got := insertAddr([]netip.AddrPort{two, one}, one)
	if want := []netip.AddrPort{one, two}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

type fakeGateway struct {
	mu           sync.Mutex
	addCalls     int
	deleteCalls  int
	externalPort int
	externalIP   net.IP
	externalErr  error
	deleteErr    error
	lease        time.Duration
	gatewayType  string
	added        chan struct{}
}

func (g *fakeGateway) Type() string {
	if g.gatewayType != "" {
		return g.gatewayType
	}
	return "fake"
}

func (g *fakeGateway) AddPortMapping(_ context.Context, _ string, _ int, _ string, requestedLifetime time.Duration) (int, time.Duration, error) {
	g.mu.Lock()
	g.addCalls++
	lease := g.lease
	g.mu.Unlock()
	if g.added != nil {
		select {
		case g.added <- struct{}{}:
		default:
		}
	}
	if lease == 0 {
		lease = requestedLifetime
	}
	return g.externalPort, lease, nil
}

func (g *fakeGateway) DeletePortMapping(context.Context, string, int) error {
	g.mu.Lock()
	g.deleteCalls++
	g.mu.Unlock()
	return g.deleteErr
}

func (g *fakeGateway) GetExternalAddress(context.Context) (net.IP, error) {
	return g.externalIP, g.externalErr
}

func TestPortMapConfigDefaultsAndInvalid(t *testing.T) {
	defaults, err := (PortMapConfig{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Timeout != defaultPortMapTimeout || defaults.Lifetime != defaultPortMapLifetime {
		t.Fatalf("defaults = %#v", defaults)
	}
	for _, config := range []PortMapConfig{{Timeout: -1}, {Lifetime: -1}, {Lifetime: time.Duration(1<<32) * time.Second}} {
		if _, err := config.withDefaults(); !errors.Is(err, ErrInvalidPortMapConfig) {
			t.Fatalf("config %#v error = %v, want ErrInvalidPortMapConfig", config, err)
		}
	}
}

func TestDiscoverUPnPGatewayCancelsAndJoinsAllProbes(t *testing.T) {
	probeStopped := make(chan struct{})
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1")}
	got, err := discoverUPnPGateway(context.Background(), []upnpGatewayProbe{
		func(context.Context) ([]portMappingGateway, error) { return []portMappingGateway{gateway}, nil },
		func(ctx context.Context) ([]portMappingGateway, error) {
			<-ctx.Done()
			close(probeStopped)
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != gateway {
		t.Fatalf("gateway = %v, want %v", got, gateway)
	}
	select {
	case <-probeStopped:
	default:
		t.Fatal("discovery returned before canceled probe stopped")
	}
}

func TestDiscoverPortMappingGatewayFallsBackToNATPMP(t *testing.T) {
	gateway := &fakeGateway{gatewayType: "NAT-PMP"}
	loserStopped := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := discoverPortMappingGatewayWith(ctx, []gatewayDiscoverer{
		func(context.Context) (portMappingGateway, error) {
			return nil, errors.New("UPnP unavailable")
		},
		func(context.Context) (portMappingGateway, error) {
			return gateway, nil
		},
		func(ctx context.Context) (portMappingGateway, error) {
			<-ctx.Done()
			close(loserStopped)
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != gateway {
		t.Fatalf("gateway = %v, want NAT-PMP gateway", got)
	}
	select {
	case <-loserStopped:
	case <-ctx.Done():
		t.Fatal("losing discovery probe did not stop after a gateway was selected")
	}
}

func TestNewPortMapperSupportsNATPMPWithDeterministicCleanup(t *testing.T) {
	gateway := &fakeGateway{gatewayType: "NAT-PMP", externalPort: 1234, externalIP: net.ParseIP("198.51.100.1")}
	mapper, err := newPortMapper(context.Background(), 4321, PortMapConfig{}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := mapper.Close(); err != nil {
		t.Fatal(err)
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if gateway.addCalls != 1 || gateway.deleteCalls != 1 {
		t.Fatalf("calls add=%d delete=%d, want 1/1", gateway.addCalls, gateway.deleteCalls)
	}
}

type blockingExternalGateway struct {
	fakeGateway
}

func (g *blockingExternalGateway) GetExternalAddress(ctx context.Context) (net.IP, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestNewPortMapperBoundsExternalAddressLookup(t *testing.T) {
	gateway := &blockingExternalGateway{fakeGateway: fakeGateway{externalPort: 1234}}
	_, err := newPortMapper(context.Background(), 4321, PortMapConfig{Timeout: time.Nanosecond}, func(context.Context) (portMappingGateway, error) {
		return gateway, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
}

func TestNewPortMapperRollsBackPartialMapping(t *testing.T) {
	gateway := &fakeGateway{externalPort: 1234, externalErr: errors.New("no address")}
	_, err := newPortMapper(context.Background(), 4321, PortMapConfig{}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err == nil {
		t.Fatal("expected error")
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if gateway.deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", gateway.deleteCalls)
	}
}

func TestPortMapperUsesGrantedLease(t *testing.T) {
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1"), lease: 2 * time.Minute}
	mapper, err := newPortMapper(context.Background(), 4321, PortMapConfig{Lifetime: 10 * time.Minute}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer mapper.Close()
	if got := mapper.Lifetime(); got != 2*time.Minute {
		t.Fatalf("mapping lifetime = %s, want 2m", got)
	}
}

func TestPortMapRenewalIntervalUsesGrantedLease(t *testing.T) {
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1"), lease: 2 * time.Minute}
	mapper, err := newPortMapper(context.Background(), 4321, PortMapConfig{Lifetime: 10 * time.Minute}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer mapper.Close()
	if got := portMapRenewalInterval(mapper); got != time.Minute {
		t.Fatalf("renewal interval = %s, want 1m", got)
	}
}

func TestPortMapperKeepsGrantedLeaseAfterAddressFailure(t *testing.T) {
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1"), lease: 10 * time.Minute}
	mapper, err := newPortMapper(context.Background(), 4321, PortMapConfig{Lifetime: 10 * time.Minute}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer mapper.Close()
	gateway.lease = 2 * time.Minute
	gateway.externalErr = errors.New("temporary address lookup failure")
	if _, err := mapper.Renew(context.Background()); err == nil {
		t.Fatal("expected address lookup failure")
	}
	if got := mapper.Lifetime(); got != 2*time.Minute {
		t.Fatalf("mapping lifetime after partial renewal = %s, want 2m", got)
	}
}

func TestPortMapRenewalFailureUsesBoundedRetry(t *testing.T) {
	mapper := &PortMapper{mappingLifetime: 10 * time.Minute}
	if got := portMapNextRenewalInterval(mapper, true); got != time.Minute {
		t.Fatalf("failure retry interval = %s, want 1m", got)
	}
}

func TestPortMapperRejectsRenewAfterClose(t *testing.T) {
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1")}
	mapper, err := newPortMapper(context.Background(), 4321, PortMapConfig{}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := mapper.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := mapper.Renew(context.Background()); !errors.Is(err, ErrPortMapperClosed) {
		t.Fatalf("renew error = %v, want ErrPortMapperClosed", err)
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if gateway.addCalls != 1 || gateway.deleteCalls != 1 {
		t.Fatalf("calls add=%d delete=%d, want 1/1", gateway.addCalls, gateway.deleteCalls)
	}
}

func TestNewPortMapperRejectsMappedUnspecifiedAddress(t *testing.T) {
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.IPv4zero}
	_, err := newPortMapper(context.Background(), 4321, PortMapConfig{}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err == nil {
		t.Fatal("expected unspecified external-address error")
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if gateway.deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", gateway.deleteCalls)
	}
}

func TestNewPortMapperReportsRollbackFailure(t *testing.T) {
	externalErr := errors.New("no external address")
	deleteErr := errors.New("delete failed")
	gateway := &fakeGateway{externalPort: 1234, externalErr: externalErr, deleteErr: deleteErr}
	_, err := newPortMapper(context.Background(), 4321, PortMapConfig{}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if !errors.Is(err, externalErr) || !errors.Is(err, deleteErr) {
		t.Fatalf("error = %v, want joined external/delete errors", err)
	}
}

func TestPortMapLoopRenewalAndShutdown(t *testing.T) {
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1"), added: make(chan struct{}, 2)}
	mapper, err := newPortMapper(context.Background(), 4321, PortMapConfig{Lifetime: time.Hour}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err != nil {
		t.Fatal(err)
	}
	<-gateway.added
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go portMapLoopWithTicks(ctx, mapper, ticks, func() { close(done) })
	ticks <- time.Now()
	<-gateway.added
	cancel()
	<-done
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if gateway.addCalls != 2 {
		t.Fatalf("add calls = %d, want 2", gateway.addCalls)
	}
	if gateway.deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", gateway.deleteCalls)
	}
}

func TestRealmClientConstructorFailureReportsMappingCleanupError(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	deleteErr := errors.New("delete failed")
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1"), deleteErr: deleteErr}
	original := createPortMapper
	createPortMapper = func(ctx context.Context, port int, config PortMapConfig) (*PortMapper, error) {
		return newPortMapper(ctx, port, config, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	}
	defer func() { createPortMapper = original }()

	_, err = NewConnClient(&Config{PortMapping: &PortMapping{Enabled: true}}, raw)
	if !errors.Is(err, deleteErr) {
		t.Fatalf("constructor error = %v, want mapping cleanup error", err)
	}
}

func TestRealmClientCloseReportsMappingCleanupError(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deleteErr := errors.New("delete failed")
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1"), deleteErr: deleteErr}
	mapper, err := newPortMapper(context.Background(), raw.LocalAddr().(*net.UDPAddr).Port, PortMapConfig{}, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn := &realmConnClient{ctx: ctx, cancel: cancel, PacketConn: raw, mapper: mapper}
	conn.wg.Add(1)
	go portMapLoop(ctx, mapper, conn.wg.Done)
	if err := conn.Close(); !errors.Is(err, deleteErr) {
		t.Fatalf("close error = %v, want mapping cleanup error", err)
	}
}

func TestRealmClientConstructorFailureCleansMappingAndContext(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1")}
	original := createPortMapper
	var ownedContext context.Context
	createPortMapper = func(ctx context.Context, port int, config PortMapConfig) (*PortMapper, error) {
		ownedContext = ctx
		return newPortMapper(ctx, port, config, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	}
	defer func() { createPortMapper = original }()

	_, err = NewConnClient(&Config{PortMapping: &PortMapping{Enabled: true}}, raw)
	if err == nil {
		t.Fatal("expected constructor error")
	}
	select {
	case <-ownedContext.Done():
	default:
		t.Fatal("constructor-owned context was not canceled")
	}
	gateway.mu.Lock()
	deletes := gateway.deleteCalls
	gateway.mu.Unlock()
	if deletes != 1 {
		t.Fatalf("delete calls = %d, want 1", deletes)
	}
	if _, err := raw.WriteTo([]byte("x"), raw.LocalAddr()); err != nil {
		t.Fatalf("caller-owned PacketConn closed on constructor failure: %v", err)
	}
}

func TestRealmServerShutdownCleansMappingAndPacketConn(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requestStarted <- struct{}{}:
		default:
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer httpServer.Close()
	host, port, err := net.SplitHostPort(httpServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gateway := &fakeGateway{externalPort: 1234, externalIP: net.ParseIP("198.51.100.1")}
	original := createPortMapper
	createPortMapper = func(ctx context.Context, port int, config PortMapConfig) (*PortMapper, error) {
		return newPortMapper(ctx, port, config, func(context.Context) (portMappingGateway, error) { return gateway, nil })
	}
	defer func() { createPortMapper = original }()

	wrapped, err := NewConnServer(&Config{Scheme: "http", Host: host, Port: port, Token: "token", ID: "id", PortMapping: &PortMapping{Enabled: true}}, raw)
	if err != nil {
		t.Fatal(err)
	}
	<-requestStarted
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	gateway.mu.Lock()
	deletes := gateway.deleteCalls
	gateway.mu.Unlock()
	if deletes != 1 {
		t.Fatalf("delete calls = %d, want 1", deletes)
	}
	if _, err := raw.WriteTo([]byte("x"), raw.LocalAddr()); err == nil {
		t.Fatal("underlying PacketConn remained open")
	}
}

func TestRealmClientCloseOwnsPacketConn(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn := &realmConnClient{ctx: ctx, cancel: cancel, PacketConn: raw}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.WriteTo([]byte("x"), raw.LocalAddr()); err == nil {
		t.Fatal("underlying PacketConn remained open")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("owned context was not canceled")
	}
}
