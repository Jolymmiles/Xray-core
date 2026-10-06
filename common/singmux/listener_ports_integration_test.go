//go:build integration

package singmux_test

import (
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
)

// listenerPorts hands out ports for test processes to listen on. Each port is
// released before its process binds it, so it comes from outside the kernel's
// automatic source-port range, where an outbound connection could take it in
// between, and no port is handed out twice in one test binary. The cursor
// starts at a random offset so that concurrent test binaries spread out.
var listenerPorts struct {
	sync.Mutex
	cursor int
	issued map[int]bool
}

// freeTCPPort returns a loopback port for a TCP listener.
func freeTCPPort(t testing.TB) int {
	t.Helper()
	return freeListenerPort(t, net.IPv4(127, 0, 0, 1), true, false)
}

// freeWildcardTCPPort returns a port for a TCP listener on every IPv4 address.
func freeWildcardTCPPort(t testing.TB) int {
	t.Helper()
	return freeListenerPort(t, net.IPv4zero, true, false)
}

// freeUDPPort returns a loopback port for a UDP listener.
func freeUDPPort(t testing.TB) int {
	t.Helper()
	return freeListenerPort(t, net.IPv4(127, 0, 0, 1), false, true)
}

// freeTCPUDPPort returns a loopback port free for both TCP and UDP, for a
// listener such as a SOCKS inbound that binds both.
func freeTCPUDPPort(t testing.TB) int {
	t.Helper()
	return freeListenerPort(t, net.IPv4(127, 0, 0, 1), true, true)
}

func freeListenerPort(t testing.TB, ip net.IP, tcp, udp bool) int {
	t.Helper()
	first, last := listenerPortRange(t)
	size := last - first + 1
	listenerPorts.Lock()
	defer listenerPorts.Unlock()
	if listenerPorts.issued == nil {
		listenerPorts.issued = make(map[int]bool)
		listenerPorts.cursor = mathrand.IntN(size)
	}
	var lastErr error
	for range min(size, 4096) {
		port := first + listenerPorts.cursor%size
		listenerPorts.cursor++
		if listenerPorts.issued[port] {
			continue
		}
		if lastErr = canListen(ip, port, tcp, udp); lastErr != nil {
			continue
		}
		listenerPorts.issued[port] = true
		return port
	}
	t.Fatalf("no free listener port in [%d, %d]: %v", first, last, lastErr)
	return 0
}

// listenerPortRange is the unprivileged range outside the kernel's automatic
// source-port range.
func listenerPortRange(t testing.TB) (int, int) {
	t.Helper()
	if runtime.GOOS != "linux" {
		// Darwin and Windows hand out source ports from 49152 upwards.
		return 1024, 49151
	}
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		t.Fatal(err)
	}
	var automaticFirst, automaticLast int
	if _, err := fmt.Sscan(string(data), &automaticFirst, &automaticLast); err != nil || automaticFirst < 1 || automaticLast > 65535 || automaticFirst > automaticLast {
		t.Fatalf("invalid Linux automatic source-port range %q: %v", data, err)
	}
	first, last := 1024, automaticFirst-1
	if last < first {
		first, last = max(1024, automaticLast+1), 65535
	}
	if first > last {
		t.Fatal("no unprivileged ports outside the Linux automatic source-port range")
	}
	return first, last
}

// canListen binds the requested transports on ip:port at the same time and
// releases them.
func canListen(ip net.IP, port int, tcp, udp bool) error {
	if udp {
		connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			return err
		}
		defer connection.Close()
	}
	if tcp {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip, Port: port})
		if err != nil {
			return err
		}
		defer listener.Close()
	}
	return nil
}
