//go:build linux && integration

package singmux_test

import (
	"fmt"
	"net"
	"os"
	"testing"
)

func TestFreeTCPUDPPortAvoidsAutomaticSourcePorts(t *testing.T) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		t.Fatal(err)
	}
	var first, last int
	if _, err := fmt.Sscan(string(data), &first, &last); err != nil {
		t.Fatal(err)
	}
	port := freeTCPUDPPort(t)
	if port >= first && port <= last {
		t.Fatalf("client listener port %d is available for automatic source-port allocation in [%d, %d] before the client starts", port, first, last)
	}
}

func TestFreeTCPUDPPortRejectsOccupiedTransport(t *testing.T) {
	for _, network := range []string{"tcp4", "udp4"} {
		t.Run(network, func(t *testing.T) {
			port := freeTCPUDPPort(t)
			address := fmt.Sprintf("127.0.0.1:%d", port)
			if network == "tcp4" {
				listener, err := net.Listen(network, address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
			} else {
				listener, err := net.ListenPacket(network, address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
			}
			if got := freeTCPUDPPort(t); got == port {
				t.Fatalf("selected occupied %s port %d", network, got)
			}
		})
	}
}
