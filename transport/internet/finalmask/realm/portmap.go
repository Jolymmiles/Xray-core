package realm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultPortMapTimeout  = 10 * time.Second
	defaultPortMapLifetime = 10 * time.Minute
	maxPortMapLifetime     = time.Duration(1<<32-1) * time.Second
	portMapDescription     = "hysteria-realm"
	portMapProtocol        = "udp"
)

var (
	ErrInvalidPortMapConfig = errors.New("invalid port mapping config")
	ErrPortMapperClosed     = errors.New("port mapper is closed")
)

type PortMapConfig struct {
	Timeout  time.Duration
	Lifetime time.Duration
}

func (c PortMapConfig) withDefaults() (PortMapConfig, error) {
	if c.Timeout == 0 {
		c.Timeout = defaultPortMapTimeout
	}
	if c.Timeout < 0 {
		return c, fmt.Errorf("%w: timeout must not be negative", ErrInvalidPortMapConfig)
	}
	if c.Lifetime == 0 {
		c.Lifetime = defaultPortMapLifetime
	}
	if c.Lifetime < 0 || c.Lifetime > maxPortMapLifetime {
		return c, fmt.Errorf("%w: lifetime must be between zero and %s", ErrInvalidPortMapConfig, maxPortMapLifetime)
	}
	return c, nil
}

type portMappingGateway interface {
	Type() string
	GetExternalAddress(context.Context) (net.IP, error)
	AddPortMapping(context.Context, string, int, string, time.Duration) (int, time.Duration, error)
	DeletePortMapping(context.Context, string, int) error
}

type gatewayDiscoverer func(context.Context) (portMappingGateway, error)

type gatewayDiscoveryResult struct {
	gateway portMappingGateway
	err     error
}

var defaultGatewayDiscoverers = []gatewayDiscoverer{
	func(ctx context.Context) (portMappingGateway, error) {
		return discoverUPnPGateway(ctx, defaultUPnPGatewayProbes)
	},
	discoverNATPMPGateway,
}

var discoverPortMappingGateway gatewayDiscoverer = func(ctx context.Context) (portMappingGateway, error) {
	return discoverPortMappingGatewayWith(ctx, defaultGatewayDiscoverers)
}

func discoverPortMappingGatewayWith(ctx context.Context, discoverers []gatewayDiscoverer) (portMappingGateway, error) {
	if len(discoverers) == 0 {
		return nil, errors.New("no port-mapping gateway discoverers configured")
	}
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan gatewayDiscoveryResult, len(discoverers))
	for _, discover := range discoverers {
		go func(discover gatewayDiscoverer) {
			gateway, err := discover(probeCtx)
			results <- gatewayDiscoveryResult{gateway: gateway, err: err}
		}(discover)
	}

	var discoveryErrors []error
	for range discoverers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err == nil && result.gateway != nil {
				cancel()
				return result.gateway, nil
			}
			if result.err != nil && !errors.Is(result.err, context.Canceled) {
				discoveryErrors = append(discoveryErrors, result.err)
			}
		}
	}
	if err := errors.Join(discoveryErrors...); err != nil {
		return nil, fmt.Errorf("port-mapping gateway discovery failed: %w", err)
	}
	return nil, errors.New("port-mapping gateway discovery returned no gateway")
}

type PortMapper struct {
	gateway      portMappingGateway
	internalPort int
	config       PortMapConfig

	lifecycleMu sync.Mutex
	closed      bool
	closeErr    error

	mu              sync.RWMutex
	externalAddr    netip.AddrPort
	mappingLifetime time.Duration
}

func NewPortMapper(ctx context.Context, internalPort int, config PortMapConfig) (*PortMapper, error) {
	return newPortMapper(ctx, internalPort, config, discoverPortMappingGateway)
}

func newPortMapper(ctx context.Context, internalPort int, config PortMapConfig, discover gatewayDiscoverer) (*PortMapper, error) {
	if internalPort <= 0 || internalPort > 65535 {
		return nil, fmt.Errorf("%w: invalid internal port %d", ErrInvalidPortMapConfig, internalPort)
	}
	var err error
	config, err = config.withDefaults()
	if err != nil {
		return nil, err
	}
	discoverCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	gateway, err := discover(discoverCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("gateway discovery failed: %w", err)
	}
	mapper := &PortMapper{gateway: gateway, internalPort: internalPort, config: config, mappingLifetime: config.Lifetime}
	if _, err := mapper.Renew(ctx); err != nil {
		if rollbackErr := mapper.Close(); rollbackErr != nil {
			return nil, errors.Join(err, fmt.Errorf("rollback port mapping: %w", rollbackErr))
		}
		return nil, err
	}
	return mapper, nil
}

func (m *PortMapper) Renew(ctx context.Context) (bool, error) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed {
		return false, ErrPortMapperClosed
	}

	opCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()
	externalPort, grantedLifetime, err := m.gateway.AddPortMapping(opCtx, portMapProtocol, m.internalPort, portMapDescription, m.config.Lifetime)
	if err != nil {
		return false, fmt.Errorf("add port mapping failed: %w", err)
	}
	if grantedLifetime <= 0 {
		return false, fmt.Errorf("gateway returned invalid mapping lifetime: %s", grantedLifetime)
	}
	m.mu.Lock()
	m.mappingLifetime = grantedLifetime
	m.mu.Unlock()
	if externalPort <= 0 || externalPort > 65535 {
		return false, fmt.Errorf("gateway returned invalid external port: %d", externalPort)
	}
	externalIP, err := m.gateway.GetExternalAddress(opCtx)
	if err != nil {
		return false, fmt.Errorf("get external address failed: %w", err)
	}
	addr, ok := netip.AddrFromSlice(externalIP)
	if ok {
		addr = addr.Unmap()
	}
	if !ok || addr.IsUnspecified() || addr.IsLoopback() {
		return false, fmt.Errorf("gateway returned unusable external address: %s", externalIP)
	}
	externalAddr := netip.AddrPortFrom(addr, uint16(externalPort))
	m.mu.Lock()
	changed := externalAddr != m.externalAddr
	m.externalAddr = externalAddr
	m.mu.Unlock()
	return changed, nil
}

func (m *PortMapper) ExternalAddr() netip.AddrPort {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.externalAddr
}

func (m *PortMapper) InternalPort() int { return m.internalPort }

func (m *PortMapper) Lifetime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mappingLifetime
}

func (m *PortMapper) GatewayType() string { return m.gateway.Type() }

func (m *PortMapper) Close() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed {
		return m.closeErr
	}
	m.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()
	m.closeErr = m.gateway.DeletePortMapping(ctx, portMapProtocol, m.internalPort)
	return m.closeErr
}
