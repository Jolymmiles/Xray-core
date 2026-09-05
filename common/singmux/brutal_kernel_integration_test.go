//go:build linux && amd64 && integration && brutalkernel

package singmux_test

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/singmux"
)

// These tests consume a preconfigured, isolated kernel; they never install a
// module or change routes. See TESTING.md for the three required rule modes.
func brutalKernelMode(t *testing.T) string {
	t.Helper()
	mode := os.Getenv("XRAY_BRUTAL_KERNEL_MODE")
	switch mode {
	case "application", "locked-route", "locked-rate":
		return mode
	default:
		t.Fatal("XRAY_BRUTAL_KERNEL_MODE must be application, locked-route, or locked-rate on an isolated TCP Brutal v2 host")
		return ""
	}
}

func TestBrutalKernelSocketPolicy(t *testing.T) {
	mode := brutalKernelMode(t)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	client, err := dialer.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})

	const applicationRate = uint64(1_000_000)
	var before [20]byte
	if mode != "application" {
		before = readBrutalKernelParams(t, server)
		if binary.NativeEndian.Uint64(before[:8]) != 12_500_000 || binary.NativeEndian.Uint64(before[12:]) == 0 {
			t.Fatalf("expected a 100 Mbps destination group, got %x", before)
		}
		raw, err := server.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var setErr error
		if err := raw.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, "brutal")
		}); err != nil {
			t.Fatal(err)
		}
		if mode == "locked-route" && !errors.Is(setErr, syscall.EPERM) {
			t.Fatalf("route must reject algorithm changes with EPERM, got %v", setErr)
		}
		if mode == "locked-rate" && setErr != nil {
			t.Fatalf("unlocked route must permit algorithm selection: %v", setErr)
		}
	}
	if err := singmux.SetBrutalOptions(server, applicationRate); err != nil {
		t.Fatal(err)
	}
	after := readBrutalKernelParams(t, server)
	if mode == "application" {
		if binary.NativeEndian.Uint64(after[:8]) != applicationRate || binary.NativeEndian.Uint64(after[12:]) != 0 {
			t.Fatalf("application rate/group not applied: %x", after)
		}
	} else if after != before {
		t.Fatalf("system rate/group changed: before=%x after=%x", before, after)
	}
}

func readBrutalKernelParams(t *testing.T, connection *net.TCPConn) [20]byte {
	t.Helper()
	var value [20]byte
	length := uint32(len(value))
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, socketErr = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, 23301,
			uintptr(unsafe.Pointer(&value[0])), uintptr(unsafe.Pointer(&length)), 0)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != 0 || length != uint32(len(value)) {
		t.Fatalf("TCP Brutal v2 parameters: error=%v length=%d, want 20 bytes", socketErr, length)
	}
	return value
}

func TestBrutalKernelSMUXProcess(t *testing.T) {
	brutalKernelMode(t)
	binary := os.Getenv("XRAY_E2E_BIN")
	if binary == "" {
		t.Fatal("XRAY_E2E_BIN must point to the candidate Xray binary")
	}
	workDir := t.TempDir()
	serverPort, socksPort := freeTCPPort(t), freeTCPUDPPort(t)
	paths := []string{filepath.Join(workDir, "server.json"), filepath.Join(workDir, "client.json")}
	for index, server := range []bool{true, false} {
		var config map[string]any
		if err := json.Unmarshal(xrayConfig(t, server, "vless", serverPort, socksPort, "smux", false, "", ""), &config); err != nil {
			t.Fatal(err)
		}
		section := "outbounds"
		if server {
			section = "inbounds"
		}
		endpoint := config[section].([]any)[0].(map[string]any)
		options := map[string]any{"enabled": true, "up": "8 Mbps", "down": "8 Mbps"}
		if server {
			endpoint["smux"] = map[string]any{"brutal-opts": options}
		} else {
			endpoint["smux"].(map[string]any)["brutal-opts"] = options
		}
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		writeConfig(t, paths[index], encoded)
	}
	server := startReadyE2EServer(t, binary, []string{"run", "-config", paths[0]}, serverPort, "")
	client := startReadyE2EClient(t, "xray", binary, []string{"run", "-config", paths[1]}, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s\nclient logs:\n%s", server.logs.String(), client.logs.String())
		}
	})
	testSOCKSTCP(t, socksPort, startTCPEcho(t).(*net.TCPAddr))
}
