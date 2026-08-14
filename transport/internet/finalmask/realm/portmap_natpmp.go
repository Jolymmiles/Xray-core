package realm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	natpmp "github.com/jackpal/go-nat-pmp"
	netroute "github.com/libp2p/go-netroute"
)

type natPMPClient interface {
	GetExternalAddress() (*natpmp.GetExternalAddressResult, error)
	AddPortMapping(protocol string, internalPort, requestedExternalPort, lifetime int) (*natpmp.AddPortMappingResult, error)
}

type natPMPClientFactory func(time.Duration) natPMPClient

type natPMPRoute interface {
	Route(net.IP) (*net.Interface, net.IP, net.IP, error)
}

var (
	newNATPMPRoute = func() (natPMPRoute, error) {
		return netroute.New()
	}
	newNATPMPClientForGateway = func(gatewayIP net.IP, timeout time.Duration) natPMPClient {
		return natpmp.NewClientWithTimeout(gatewayIP, timeout)
	}
)

type natPMPGateway struct {
	newClient        natPMPClientFactory
	operationToken   chan struct{}
	externalPorts    map[int]int
	mappingAttempted map[int]bool
}

func newNATPMPGateway(client natPMPClient) *natPMPGateway {
	return newNATPMPGatewayWithFactory(func(time.Duration) natPMPClient { return client })
}

func newNATPMPGatewayWithFactory(factory natPMPClientFactory) *natPMPGateway {
	operationToken := make(chan struct{}, 1)
	operationToken <- struct{}{}
	return &natPMPGateway{
		newClient:        factory,
		operationToken:   operationToken,
		externalPorts:    make(map[int]int),
		mappingAttempted: make(map[int]bool),
	}
}

func (g *natPMPGateway) Type() string { return "NAT-PMP" }

func (g *natPMPGateway) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.operationToken:
		return nil
	}
}

func (g *natPMPGateway) release() {
	g.operationToken <- struct{}{}
}

func (g *natPMPGateway) clientForContext(ctx context.Context) (natPMPClient, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout := defaultPortMapTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	return g.newClient(timeout), nil
}

func (g *natPMPGateway) GetExternalAddress(ctx context.Context) (net.IP, error) {
	if err := g.acquire(ctx); err != nil {
		return nil, err
	}
	defer g.release()
	client, err := g.clientForContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := client.GetExternalAddress()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("NAT-PMP returned an empty external-address response")
	}
	return net.IPv4(result.ExternalIPAddress[0], result.ExternalIPAddress[1], result.ExternalIPAddress[2], result.ExternalIPAddress[3]), nil
}

func (g *natPMPGateway) AddPortMapping(ctx context.Context, protocol string, internalPort int, _ string, lifetime time.Duration) (int, time.Duration, error) {
	if err := g.acquire(ctx); err != nil {
		return 0, 0, err
	}
	defer g.release()
	client, err := g.clientForContext(ctx)
	if err != nil {
		return 0, 0, err
	}
	lifetimeSeconds := lifetime / time.Second
	if lifetimeSeconds <= 0 || lifetimeSeconds > math.MaxUint32 {
		return 0, 0, fmt.Errorf("invalid NAT-PMP mapping lifetime %s", lifetime)
	}

	requestedExternalPort := g.externalPorts[internalPort]
	if requestedExternalPort == 0 {
		requestedExternalPort = internalPort
	}
	g.mappingAttempted[internalPort] = true
	result, err := client.AddPortMapping(protocol, internalPort, requestedExternalPort, int(lifetimeSeconds))
	if err != nil {
		return 0, 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	if result == nil || result.MappedExternalPort == 0 {
		return 0, 0, errors.New("NAT-PMP returned an invalid port-mapping response")
	}
	grantedLifetime := time.Duration(result.PortMappingLifetimeInSeconds) * time.Second
	if grantedLifetime <= 0 {
		return 0, 0, errors.New("NAT-PMP returned an invalid mapping lifetime")
	}
	g.externalPorts[internalPort] = int(result.MappedExternalPort)
	return int(result.MappedExternalPort), grantedLifetime, nil
}

func (g *natPMPGateway) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	if err := g.acquire(ctx); err != nil {
		return err
	}
	defer g.release()
	if !g.mappingAttempted[internalPort] {
		return nil
	}
	client, err := g.clientForContext(ctx)
	if err != nil {
		return err
	}
	// RFC 6886 and go-nat-pmp define deletion as a mapping request with both
	// the requested external port and lifetime set to zero.
	_, err = client.AddPortMapping(protocol, internalPort, 0, 0)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	delete(g.externalPorts, internalPort)
	delete(g.mappingAttempted, internalPort)
	return nil
}

func discoverNATPMPGateway(ctx context.Context) (portMappingGateway, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	router, err := newNATPMPRoute()
	if err != nil {
		return nil, fmt.Errorf("read routing table: %w", err)
	}
	_, gatewayIP, _, err := router.Route(net.IPv4(1, 1, 1, 1))
	if err != nil {
		return nil, fmt.Errorf("find default gateway: %w", err)
	}
	if gatewayIP == nil || gatewayIP.IsUnspecified() {
		return nil, errors.New("default route has no NAT-PMP gateway")
	}

	gateway := newNATPMPGatewayWithFactory(func(operationTimeout time.Duration) natPMPClient {
		return newNATPMPClientForGateway(gatewayIP, operationTimeout)
	})
	if _, err := gateway.GetExternalAddress(ctx); err != nil {
		return nil, fmt.Errorf("probe NAT-PMP gateway %s: %w", gatewayIP, err)
	}
	return gateway, nil
}
