package scenarios

import (
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestVersionSkewTCPPortsAreDistinct(t *testing.T) {
	ports := pickVersionSkewTCPPorts(t, 3)
	seen := make(map[uint16]bool)
	for _, port := range ports {
		if port == 0 || seen[uint16(port)] {
			t.Fatalf("version-skew TCP ports must be nonzero and distinct: %v", ports)
		}
		seen[uint16(port)] = true
	}
}

// pickVersionSkewTCPPorts holds each listener until the entire group has been
// allocated, so the kernel cannot return the same TCP port twice in one topology.
func pickVersionSkewTCPPorts(t *testing.T, count int) []net.Port {
	t.Helper()
	return reserveVersionSkewTCPPorts(t, count, stdnet.Listen)
}

func reserveVersionSkewTCPPorts(t *testing.T, count int, listen func(string, string) (stdnet.Listener, error)) []net.Port {
	t.Helper()
	listeners := make([]stdnet.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			if err := listener.Close(); err != nil {
				t.Errorf("close reserved TCP port: %v", err)
			}
		}
	}()
	ports := make([]net.Port, 0, count)
	for range count {
		listener, err := listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve version-skew TCP port: %v", err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, net.Port(listener.Addr().(*stdnet.TCPAddr).Port))
	}
	return ports
}

func TestVersionSkewTCPPortsRemainReservedDuringAllocation(t *testing.T) {
	var earlier []string
	listen := func(network, address string) (stdnet.Listener, error) {
		for _, addr := range earlier {
			probe, err := stdnet.Listen("tcp4", addr)
			if err == nil {
				if err := probe.Close(); err != nil {
					t.Errorf("close probe: %v", err)
				}
				t.Errorf("previous port %s was released before allocation finished", addr)
			}
		}
		listener, err := stdnet.Listen(network, address)
		if err == nil {
			earlier = append(earlier, listener.Addr().String())
		}
		return listener, err
	}
	reserveVersionSkewTCPPorts(t, 3, listen)
}
