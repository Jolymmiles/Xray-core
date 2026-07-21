//go:build integration && linux

package singmux_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type interfaceHealthSnapshot map[string]uint64

func captureLoopbackHealth(t *testing.T) interfaceHealthSnapshot {
	t.Helper()
	snapshot := make(interfaceHealthSnapshot)
	paths := map[string]string{
		"rx_errors":         "/sys/class/net/lo/statistics/rx_errors",
		"tx_errors":         "/sys/class/net/lo/statistics/tx_errors",
		"rx_dropped":        "/sys/class/net/lo/statistics/rx_dropped",
		"tx_dropped":        "/sys/class/net/lo/statistics/tx_dropped",
		"rx_crc_errors":     "/sys/class/net/lo/statistics/rx_crc_errors",
		"tx_carrier_errors": "/sys/class/net/lo/statistics/tx_carrier_errors",
		"collisions":        "/sys/class/net/lo/statistics/collisions",
		"carrier_changes":   "/sys/class/net/lo/carrier_changes",
	}
	for name, path := range paths {
		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read loopback health counter %s: %v", name, err)
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(content)), 10, 64)
		if err != nil {
			t.Fatalf("parse loopback health counter %s: %v", name, err)
		}
		snapshot[name] = value
	}
	t.Logf("loopback health baseline (historical, not cleared): %s", formatHealthSnapshot(snapshot))
	return snapshot
}

func assertLoopbackHealth(t *testing.T, baseline interfaceHealthSnapshot) {
	t.Helper()
	after := captureLoopbackHealth(t)
	for name, initial := range baseline {
		delta := after[name] - initial
		t.Logf("loopback health delta %s=%d", name, delta)
		if delta != 0 {
			t.Errorf("loopback counter %s increased by %d during SMUX stress", name, delta)
		}
	}
}

func formatHealthSnapshot(snapshot interfaceHealthSnapshot) string {
	result := ""
	for name, value := range snapshot {
		result += fmt.Sprintf("%s=%d ", name, value)
	}
	return strings.TrimSpace(result)
}

func captureProcessResources(t *testing.T, pid int) processResourceSnapshot {
	t.Helper()
	content, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("read process status for %d: %v", pid, err)
	}
	var snapshot processResourceSnapshot
	for line := range strings.SplitSeq(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "VmRSS:":
			snapshot.rssKiB, _ = strconv.ParseUint(fields[1], 10, 64)
		case "Threads:":
			snapshot.threads, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	fileDescriptors, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatalf("read file descriptors for %d: %v", pid, err)
	}
	snapshot.fds = uint64(len(fileDescriptors))
	return snapshot
}
