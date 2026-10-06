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

// pickers are the helpers that hand a test process a port to listen on later.
var pickers = []struct {
	name string
	pick func(testing.TB) int
}{
	{"tcp", freeTCPPort},
	{"wildcard-tcp", freeWildcardTCPPort},
	{"udp", freeUDPPort},
	{"tcp+udp", freeTCPUDPPort},
}

// Each port is released before its process binds it. A port from the
// automatic source-port range can be taken by an outbound connection in
// between, and the process then fails with "address already in use".
func TestListenerPortsAvoidAutomaticSourcePorts(t *testing.T) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		t.Fatal(err)
	}
	var first, last int
	if _, err := fmt.Sscan(string(data), &first, &last); err != nil {
		t.Fatal(err)
	}
	for _, picker := range pickers {
		for range 8 {
			if port := picker.pick(t); port >= first && port <= last {
				t.Errorf("%s handed out port %d from the automatic source-port range [%d, %d]", picker.name, port, first, last)
				break
			}
		}
	}
}

// Ports are handed out before anything binds them, so a helper must not hand
// out the same port twice, e.g. for a server and its client in one scenario.
func TestListenerPortsAreNotHandedOutTwice(t *testing.T) {
	issued := make(map[int]string)
	for range 32 {
		for _, picker := range pickers {
			port := picker.pick(t)
			if earlier, ok := issued[port]; ok {
				t.Fatalf("%s handed out port %d, already handed out by %s", picker.name, port, earlier)
			}
			issued[port] = picker.name
		}
	}
}
