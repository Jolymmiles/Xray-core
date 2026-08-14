package realm

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	natpmp "github.com/jackpal/go-nat-pmp"
)

type natPMPCall struct {
	protocol              string
	internalPort          int
	requestedExternalPort int
	lifetime              int
}

type fakeNATPMPClient struct {
	externalAddress [4]byte
	mappedPort      uint16
	grantedLifetime uint32
	addErr          error
	calls           []natPMPCall
}

func (c *fakeNATPMPClient) GetExternalAddress() (*natpmp.GetExternalAddressResult, error) {
	return &natpmp.GetExternalAddressResult{ExternalIPAddress: c.externalAddress}, nil
}

func (c *fakeNATPMPClient) AddPortMapping(protocol string, internalPort, requestedExternalPort, lifetime int) (*natpmp.AddPortMappingResult, error) {
	c.calls = append(c.calls, natPMPCall{
		protocol:              protocol,
		internalPort:          internalPort,
		requestedExternalPort: requestedExternalPort,
		lifetime:              lifetime,
	})
	if c.addErr != nil && lifetime > 0 {
		return nil, c.addErr
	}
	grantedLifetime := c.grantedLifetime
	if grantedLifetime == 0 {
		grantedLifetime = uint32(lifetime)
	}
	return &natpmp.AddPortMappingResult{
		InternalPort:                 uint16(internalPort),
		MappedExternalPort:           c.mappedPort,
		PortMappingLifetimeInSeconds: grantedLifetime,
	}, nil
}

func TestNATPMPGatewayUsesRemainingDeadlinePerRPC(t *testing.T) {
	client := &fakeNATPMPClient{externalAddress: [4]byte{198, 51, 100, 7}, mappedPort: 54321}
	timeouts := make(chan time.Duration, 2)
	gateway := newNATPMPGatewayWithFactory(func(timeout time.Duration) natPMPClient {
		timeouts <- timeout
		return client
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, _, err := gateway.AddPortMapping(ctx, "udp", 4321, "ignored", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.GetExternalAddress(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		timeout := <-timeouts
		if timeout <= 0 || timeout > time.Second {
			t.Fatalf("RPC timeout = %s, want within context deadline", timeout)
		}
	}
}

func TestNATPMPGatewayLockWaitHonorsContext(t *testing.T) {
	gateway := newNATPMPGateway(&fakeNATPMPClient{})
	<-gateway.operationToken
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := gateway.GetExternalAddress(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	gateway.operationToken <- struct{}{}
}

func TestNATPMPGatewayRenewAndDelete(t *testing.T) {
	client := &fakeNATPMPClient{
		externalAddress: [4]byte{198, 51, 100, 7},
		mappedPort:      54321,
		grantedLifetime: 120,
	}
	gateway := newNATPMPGateway(client)

	externalPort, grantedLifetime, err := gateway.AddPortMapping(context.Background(), "udp", 4321, "ignored", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if externalPort != 54321 || grantedLifetime != 2*time.Minute {
		t.Fatalf("mapping = %d/%s, want 54321/2m", externalPort, grantedLifetime)
	}
	if _, _, err := gateway.AddPortMapping(context.Background(), "udp", 4321, "ignored", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	externalIP, err := gateway.GetExternalAddress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !externalIP.Equal(net.IPv4(198, 51, 100, 7)) {
		t.Fatalf("external IP = %v", externalIP)
	}
	if err := gateway.DeletePortMapping(context.Background(), "udp", 4321); err != nil {
		t.Fatal(err)
	}

	if len(client.calls) != 3 {
		t.Fatalf("calls = %d, want 3", len(client.calls))
	}
	if got := client.calls[0]; got.protocol != "udp" || got.internalPort != 4321 || got.requestedExternalPort != 4321 || got.lifetime != 600 {
		t.Fatalf("add call = %#v", got)
	}
	if got := client.calls[1]; got.protocol != "udp" || got.internalPort != 4321 || got.requestedExternalPort != 54321 || got.lifetime != 600 {
		t.Fatalf("renew call = %#v", got)
	}
	if got := client.calls[2]; got.protocol != "udp" || got.internalPort != 4321 || got.requestedExternalPort != 0 || got.lifetime != 0 {
		t.Fatalf("delete call = %#v", got)
	}
}

type fakeNATPMPRoute struct {
	gateway net.IP
}

func (r fakeNATPMPRoute) Route(net.IP) (*net.Interface, net.IP, net.IP, error) {
	return nil, r.gateway, nil, nil
}

func TestNATPMPGatewayDeletesAfterAmbiguousAdd(t *testing.T) {
	addErr := errors.New("mapping response lost")
	client := &fakeNATPMPClient{addErr: addErr}
	gateway := newNATPMPGateway(client)
	if _, _, err := gateway.AddPortMapping(context.Background(), "udp", 4321, "ignored", time.Minute); !errors.Is(err, addErr) {
		t.Fatalf("add error = %v, want response-lost error", err)
	}
	if err := gateway.DeletePortMapping(context.Background(), "udp", 4321); err != nil {
		t.Fatal(err)
	}
	if len(client.calls) != 2 || client.calls[1].requestedExternalPort != 0 || client.calls[1].lifetime != 0 {
		t.Fatalf("calls = %#v, want add followed by zero-lifetime delete", client.calls)
	}
}

func TestDiscoverNATPMPGatewayProductionWiring(t *testing.T) {
	originalRoute := newNATPMPRoute
	originalClient := newNATPMPClientForGateway
	t.Cleanup(func() {
		newNATPMPRoute = originalRoute
		newNATPMPClientForGateway = originalClient
	})
	gatewayIP := net.IPv4(192, 0, 2, 1)
	client := &fakeNATPMPClient{externalAddress: [4]byte{198, 51, 100, 7}}
	newNATPMPRoute = func() (natPMPRoute, error) { return fakeNATPMPRoute{gateway: gatewayIP}, nil }
	newNATPMPClientForGateway = func(gotIP net.IP, timeout time.Duration) natPMPClient {
		if !gotIP.Equal(gatewayIP) {
			t.Fatalf("gateway IP = %v, want %v", gotIP, gatewayIP)
		}
		if timeout <= 0 || timeout > time.Second {
			t.Fatalf("timeout = %s, want within context deadline", timeout)
		}
		return client
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	gateway, err := discoverNATPMPGateway(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gateway.Type() != "NAT-PMP" {
		t.Fatalf("gateway type = %q", gateway.Type())
	}
}

func TestDiscoverNATPMPGatewayHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := discoverNATPMPGateway(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}
