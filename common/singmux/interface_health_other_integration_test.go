//go:build integration && !linux

package singmux_test

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

type interfaceHealthSnapshot map[string]uint64

func captureLoopbackHealth(t *testing.T) interfaceHealthSnapshot {
	t.Helper()
	t.Log("network interface health counters are a Linux release gate; this platform runs functional stress only")
	return nil
}

func assertLoopbackHealth(t *testing.T, _ interfaceHealthSnapshot) {
	t.Helper()
}

func captureProcessResources(t *testing.T, pid int) processResourceSnapshot {
	t.Helper()
	output, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		t.Logf("process resource sampling is unavailable: %v", err)
		return processResourceSnapshot{}
	}
	fields := strings.Fields(string(output))
	if len(fields) < 1 {
		return processResourceSnapshot{}
	}
	rss, _ := strconv.ParseUint(fields[0], 10, 64)
	return processResourceSnapshot{rssKiB: rss}
}
