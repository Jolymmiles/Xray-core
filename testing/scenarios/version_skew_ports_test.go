package scenarios

import (
	"errors"
	stdnet "net"
	"syscall"
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

func TestDualTransportPortAvoidsOccupiedTCP(t *testing.T) {
	var occupied *stdnet.TCPListener
	var heldUDP *stdnet.UDPConn
	for range 128 {
		udp, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		addr := udp.LocalAddr().(*stdnet.UDPAddr)
		tcp, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: addr.IP, Port: addr.Port})
		if err != nil {
			if closeErr := udp.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
			t.Fatal(err)
		}
		occupied, heldUDP = tcp, udp
		break
	}
	if occupied == nil {
		t.Fatal("cannot reserve a TCP/UDP pair after 128 attempts")
	}
	t.Cleanup(func() {
		if err := occupied.Close(); err != nil {
			t.Error(err)
		}
		if heldUDP != nil {
			if err := heldUDP.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	addr := occupied.Addr().(*stdnet.TCPAddr)
	port := reserveDualTransportPort(t, func() (*stdnet.UDPConn, error) {
		if heldUDP != nil {
			udp := heldUDP
			heldUDP = nil // The allocator owns and closes this socket.
			return udp, nil
		}
		return stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	})
	if int(port) == addr.Port {
		t.Fatalf("selected TCP-occupied port %d", port)
	}
	udp, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: addr.IP, Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: addr.IP, Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
}

// pickDualTransportPort finds a loopback port available to both HTTP/2 and HTTP/3.
func pickDualTransportPort(t *testing.T) net.Port {
	t.Helper()
	return reserveDualTransportPort(t, func() (*stdnet.UDPConn, error) {
		return stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	})
}

func reserveDualTransportPort(t *testing.T, listenUDP func() (*stdnet.UDPConn, error)) net.Port {
	t.Helper()
	for range 128 {
		udp, err := listenUDP()
		if err != nil {
			t.Fatalf("reserve UDP port: %v", err)
		}
		port := udp.LocalAddr().(*stdnet.UDPAddr).Port
		tcp, listenErr := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: port})
		if err := udp.Close(); err != nil {
			if tcp != nil {
				if closeErr := tcp.Close(); closeErr != nil {
					t.Errorf("close TCP reservation: %v", closeErr)
				}
			}
			t.Fatalf("close UDP reservation: %v", err)
		}
		if listenErr != nil {
			if errors.Is(listenErr, syscall.EADDRINUSE) {
				continue
			}
			t.Fatalf("reserve TCP port %d: %v", port, listenErr)
		}
		if err := tcp.Close(); err != nil {
			t.Fatalf("close TCP reservation: %v", err)
		}
		return net.Port(port)
	}
	t.Fatal("cannot reserve a port for both TCP and UDP after 128 attempts")
	return 0
}
