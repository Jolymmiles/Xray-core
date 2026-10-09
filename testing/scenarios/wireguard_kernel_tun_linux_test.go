//go:build linux

package scenarios

import (
	"bytes"
	"context"
	"errors"
	stdnet "net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy/wireguard"
)

// wireguardKernelTunBinary names the environment variable through which
// TestWireguardKernelTun hands the Xray binary to its copy in new
// namespaces. Only that copy has it set.
const wireguardKernelTunBinary = "XRAY_TEST_WIREGUARD_KERNEL_TUN_BINARY"

// TestWireguardKernelTun runs the TestWireguard scenario with the client on a
// kernel TUN, the stack Xray picks when it has CAP_NET_ADMIN. The TUN device
// and the sysctls the client writes must not reach the host, so the scenario
// runs in a copy of this test binary in new network and PID namespaces. When
// the copy exits, the kernel kills every process left in them and the
// network namespace goes away with its devices and settings.
func TestWireguardKernelTun(t *testing.T) {
	if binary := os.Getenv(wireguardKernelTunBinary); binary != "" {
		testBinaryPath = binary
		runWireguardKernelTunScenario(t)
		return
	}
	common.Must(BuildXray())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWireguardKernelTun$", "-test.v", "-test.count=1")
	child.Env = append(os.Environ(), wireguardKernelTunBinary+"="+testBinaryPath)
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWPID}
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if err := child.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("new network and PID namespaces need CAP_SYS_ADMIN: %v", err)
		}
		t.Fatal(err)
	}
	err := child.Wait()
	if ctx.Err() != nil || err != nil || !strings.Contains(output.String(), "--- PASS: TestWireguardKernelTun") {
		t.Fatalf("kernel TUN scenario in its own namespaces: %v (context: %v)\n%s", err, ctx.Err(), output.String())
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.Contains(line, "wireguard_kernel_tun_linux_test.go:") {
			t.Log(strings.TrimSpace(line))
		}
	}
}

// runWireguardKernelTunScenario sets up the fresh network namespace of the
// copy and runs the scenario with the client on a kernel TUN.
func runWireguardKernelTunScenario(t *testing.T) {
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.Attrs().Name != "lo" {
			t.Fatalf("not a fresh network namespace: it has %s; refusing to change it", link.Attrs().Name)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}
	// The scenario needs a host address other than loopback.
	host := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "xt0"}}
	if err := netlink.LinkAdd(host); err != nil {
		t.Fatal(err)
	}
	address, err := netlink.ParseAddr("198.18.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(host, address); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(host); err != nil {
		t.Fatal(err)
	}
	// Both ends of the tunnel share this namespace, so the decrypted replies
	// carry a source address that is local here, and Linux drops them as
	// martians unless accept_local is set. Replies from a remote network carry
	// a foreign address and need no such setting.
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/accept_local", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if supported, err := wireguard.KernelTunSupported(); !supported {
		t.Fatalf("the WireGuard client would not use a kernel TUN: %v", err)
	}
	runWireguardScenario(t, false, assertClientCarriedByKernelTun)
}

// assertClientCarriedByKernelTun checks that the client's traffic crossed a
// kernel TUN holding the client's tunnel address, in both directions.
func assertClientCarriedByKernelTun(t *testing.T) {
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	clientAddress := stdnet.IPv4(10, 0, 0, 2)
	for _, link := range links {
		if link.Type() != "tuntap" {
			continue
		}
		addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			if !address.IP.Equal(clientAddress) {
				continue
			}
			statistics := link.Attrs().Statistics
			if statistics == nil || statistics.TxPackets == 0 || statistics.RxPackets == 0 {
				t.Fatalf("kernel TUN %s carried no traffic both ways: %+v", link.Attrs().Name, statistics)
			}
			t.Logf("kernel TUN %s carried %d packets into the tunnel and %d out of it", link.Attrs().Name, statistics.TxPackets, statistics.RxPackets)
			return
		}
	}
	t.Fatalf("no kernel TUN holds the client address %s", clientAddress)
}
