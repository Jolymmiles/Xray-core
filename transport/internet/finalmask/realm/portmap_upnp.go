package realm

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

var errNoUPnPGateway = errors.New("no UPnP gateway found")

type upnpMappingClient interface {
	GetExternalIPAddressCtx(context.Context) (string, error)
	AddPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMappingCtx(context.Context, string, uint16, string) error
}

type upnpGateway struct {
	client     upnpMappingClient
	deviceHost string
	typ        string

	mu    sync.Mutex
	ports map[int]int
}

func (g *upnpGateway) Type() string { return g.typ }

func (g *upnpGateway) GetExternalAddress(ctx context.Context) (net.IP, error) {
	address, err := g.client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid external address %q", address)
	}
	return ip, nil
}

func (g *upnpGateway) internalAddress(ctx context.Context) (net.IP, error) {
	host := g.deviceHost
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	gatewayIP := net.ParseIP(strings.Trim(host, "[]"))
	if gatewayIP == nil {
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve gateway address %q: %w", g.deviceHost, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve gateway address %q: no addresses", g.deviceHost)
		}
		gatewayIP = addresses[0]
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			ipNetwork, ok := address.(*net.IPNet)
			if ok && ipNetwork.Contains(gatewayIP) {
				return ipNetwork.IP, nil
			}
		}
	}
	return nil, errors.New("no local address for UPnP gateway")
}

func (g *upnpGateway) AddPortMapping(ctx context.Context, protocol string, internalPort int, description string, lifetime time.Duration) (int, time.Duration, error) {
	internalIP, err := g.internalAddress(ctx)
	if err != nil {
		return 0, 0, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	candidates := make([]int, 0, 4)
	if previous := g.ports[internalPort]; previous != 0 {
		candidates = append(candidates, previous)
	}
	for len(candidates) < 4 {
		randomPort, err := rand.Int(rand.Reader, big.NewInt(65536-10000))
		if err != nil {
			return 0, 0, fmt.Errorf("generate external port: %w", err)
		}
		candidates = append(candidates, int(randomPort.Int64())+10000)
	}
	var lastErr error
	for _, externalPort := range candidates {
		lastErr = g.client.AddPortMappingCtx(ctx, "", uint16(externalPort), strings.ToUpper(protocol), uint16(internalPort), internalIP.String(), true, description, uint32(lifetime/time.Second))
		if lastErr == nil {
			g.ports[internalPort] = externalPort
			return externalPort, lifetime, nil
		}
	}
	return 0, 0, lastErr
}

func (g *upnpGateway) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	externalPort := g.ports[internalPort]
	if externalPort == 0 {
		return nil
	}
	if err := g.client.DeletePortMappingCtx(ctx, "", uint16(externalPort), strings.ToUpper(protocol)); err != nil {
		return err
	}
	delete(g.ports, internalPort)
	return nil
}

type upnpGatewayProbe func(context.Context) ([]portMappingGateway, error)

type upnpProbeResult struct {
	gateways []portMappingGateway
	err      error
}

func discoverUPnPGateway(ctx context.Context, probes []upnpGatewayProbe) (portMappingGateway, error) {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan upnpProbeResult, len(probes))
	for _, probe := range probes {
		go func() {
			gateways, err := probe(probeCtx)
			results <- upnpProbeResult{gateways: gateways, err: err}
		}()
	}
	var selected portMappingGateway
	var discoveryErr error
	for range probes {
		result := <-results
		if selected == nil && len(result.gateways) != 0 {
			selected = result.gateways[0]
			cancel()
		}
		if discoveryErr == nil && result.err != nil && !errors.Is(result.err, context.Canceled) {
			discoveryErr = result.err
		}
	}
	if selected != nil {
		return selected, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if discoveryErr != nil {
		return nil, discoveryErr
	}
	return nil, errNoUPnPGateway
}

func gatewayFromService(client upnpMappingClient, root *goupnp.RootDevice, typ string) (portMappingGateway, error) {
	if root == nil {
		return nil, errors.New("UPnP service has no root device")
	}
	deviceURL := root.URLBase
	if deviceURL.Host == "" {
		return nil, errors.New("UPnP service has no device address")
	}
	return &upnpGateway{client: client, deviceHost: deviceURL.Host, typ: typ, ports: make(map[int]int)}, nil
}

var defaultUPnPGatewayProbes = []upnpGatewayProbe{
	func(ctx context.Context) ([]portMappingGateway, error) {
		clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
		return wrapIG2IP2Clients(clients), err
	},
	func(ctx context.Context) ([]portMappingGateway, error) {
		clients, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
		return wrapIG2IP1Clients(clients), err
	},
	func(ctx context.Context) ([]portMappingGateway, error) {
		clients, _, err := internetgateway1.NewWANIPConnection1ClientsCtx(ctx)
		return wrapIG1IP1Clients(clients), err
	},
	func(ctx context.Context) ([]portMappingGateway, error) {
		clients, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx)
		return wrapIG2PPP1Clients(clients), err
	},
	func(ctx context.Context) ([]portMappingGateway, error) {
		clients, _, err := internetgateway1.NewWANPPPConnection1ClientsCtx(ctx)
		return wrapIG1PPP1Clients(clients), err
	},
}

func wrapIG2IP2Clients(clients []*internetgateway2.WANIPConnection2) []portMappingGateway {
	gateways := make([]portMappingGateway, 0, len(clients))
	for _, client := range clients {
		if gateway, err := gatewayFromService(client, client.RootDevice, "UPnP (IG2-IP2)"); err == nil {
			gateways = append(gateways, gateway)
		}
	}
	return gateways
}

func wrapIG2IP1Clients(clients []*internetgateway2.WANIPConnection1) []portMappingGateway {
	gateways := make([]portMappingGateway, 0, len(clients))
	for _, client := range clients {
		if gateway, err := gatewayFromService(client, client.RootDevice, "UPnP (IG2-IP1)"); err == nil {
			gateways = append(gateways, gateway)
		}
	}
	return gateways
}

func wrapIG1IP1Clients(clients []*internetgateway1.WANIPConnection1) []portMappingGateway {
	gateways := make([]portMappingGateway, 0, len(clients))
	for _, client := range clients {
		if gateway, err := gatewayFromService(client, client.RootDevice, "UPnP (IG1-IP1)"); err == nil {
			gateways = append(gateways, gateway)
		}
	}
	return gateways
}

func wrapIG2PPP1Clients(clients []*internetgateway2.WANPPPConnection1) []portMappingGateway {
	gateways := make([]portMappingGateway, 0, len(clients))
	for _, client := range clients {
		if gateway, err := gatewayFromService(client, client.RootDevice, "UPnP (IG2-PPP1)"); err == nil {
			gateways = append(gateways, gateway)
		}
	}
	return gateways
}

func wrapIG1PPP1Clients(clients []*internetgateway1.WANPPPConnection1) []portMappingGateway {
	gateways := make([]portMappingGateway, 0, len(clients))
	for _, client := range clients {
		if gateway, err := gatewayFromService(client, client.RootDevice, "UPnP (IG1-PPP1)"); err == nil {
			gateways = append(gateways, gateway)
		}
	}
	return gateways
}
