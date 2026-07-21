//go:build integration && linux && remnanode_release

package singmux_test

import (
	"net"
	"os"
	"testing"
)

func TestRemnaNodeLinuxReleaseEnvironment(t *testing.T) {
	if got := os.Getenv("XRAY_E2E_YT_INTERFACE"); got != "yt" {
		t.Fatalf("XRAY_E2E_YT_INTERFACE=%q, want yt for the production release gate", got)
	}
	if os.Getenv("XRAY_E2E_YT_IPV6") == "" {
		t.Fatal("XRAY_E2E_YT_IPV6 must name an IPv6 address assigned to yt")
	}
	if _, err := net.InterfaceByName("yt"); err != nil {
		t.Fatalf("production interface yt is unavailable: %v", err)
	}
	_ = deploymentIPv6Address(t)
}
