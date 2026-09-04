//go:build integration

package singmux_test

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSMUXNegotiatedHalfCloseProcessMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level negotiated SMUX half-close")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(t, workDir)
	destination := startShortResponseTCPServer(t)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	for _, security := range []string{"tls", "reality"} {
		for _, padding := range []bool{false, true} {
			t.Run(security+map[bool]string{false: "/padding=false", true: "/padding=true"}[padding], func(t *testing.T) {
				runNegotiatedSMUXProcess(t, workDir, xray, certificate, privateKey, security, padding, destination, tcpEcho)
			})
		}
	}
	if !t.Failed() {
		t.Log("SMUX_NEGOTIATED_HALF_CLOSE_OK")
	}
}

func runNegotiatedSMUXProcess(t *testing.T, workDir, xray, certificate, privateKey, security string, padding bool, destination, tcpEcho *net.TCPAddr) {
	t.Helper()
	serverPort, socksPort := freeTCPPort(t), freeTCPPort(t)
	dir := filepath.Join(workDir, t.Name())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	realityTarget := ""
	if security == "reality" {
		realityTarget = startRealityCoverServer(t, certificate, privateKey)
	}
	serverPath, clientPath := filepath.Join(dir, "server.json"), filepath.Join(dir, "client.json")
	writeConfig(t, serverPath, xrayVLESSTCPConfig(t, true, serverPort, 0, security, "", certificate, privateKey, realityTarget))
	clientConfig := negotiatedSMUXConfig(t, xrayVLESSTCPConfig(t, false, serverPort, socksPort, security, "", certificate, "", ""), padding, "require")
	writeConfig(t, clientPath, clientConfig)
	server := startE2EProcess(t, xray, "run", "-config", serverPath)
	waitTCP(t, server, serverPort)
	client := startE2EProcess(t, xray, "run", "-config", clientPath)
	waitSOCKS(t, client, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
			t.Logf("client logs:\n%s", client.logs.String())
		}
	})
	if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if err := runShortSOCKSRequest(socksPort, destination, 21, true); err != nil {
		t.Fatalf("negotiated half-close: %v", err)
	}
	if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
		t.Fatalf("sibling follow-up: %v", err)
	}
}

// This is the parent of the commit that introduced negotiated SMUX half-close.
// It accepts legacy carrier versions 0/1, so an auto client must really fall back.
const legacySMUXServerRevision = "d8a67242bb255b23ddc92338ac8bc98d66b45088"

func TestSMUXAutoFallbackLegacyXray(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level SMUX auto fallback")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	legacyXray := buildLegacySMUXServer(t, workDir, xrayRoot)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	for _, padding := range []bool{false, true} {
		t.Run(map[bool]string{false: "padding=false", true: "padding=true"}[padding], func(t *testing.T) {
			serverPort, socksPort := freeTCPPort(t), freeTCPPort(t)
			dir := filepath.Join(workDir, t.Name())
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			serverPath := filepath.Join(dir, "server.json")
			writeConfig(t, serverPath, xrayConfig(t, true, "vless", serverPort, 0, "smux", padding, certificate, privateKey))
			server := startE2EProcess(t, legacyXray, "run", "-config", serverPath)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("server logs:\n%s", server.logs.String())
				}
			})
			waitTCP(t, server, serverPort)

			// Reject a fixture that already negotiates the extension: a successful
			// auto connection alone would then never exercise fallback.
			requirePort := freeTCPPort(t)
			requirePath := filepath.Join(dir, "require.json")
			writeConfig(t, requirePath, negotiatedSMUXConfig(t, xrayConfig(t, false, "vless", serverPort, requirePort, "smux", padding, certificate, ""), padding, "require"))
			requireClient := startE2EProcess(t, xray, "run", "-config", requirePath)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("require client logs:\n%s", requireClient.logs.String())
				}
			})
			waitSOCKS(t, requireClient, requirePort)
			if err := runSOCKSTCP(requirePort, tcpEcho); err == nil {
				t.Fatal("legacy Xray server unexpectedly accepted required half-close negotiation")
			}
			stopE2EProcess(t, requireClient)

			clientPath := filepath.Join(dir, "client.json")
			clientConfig := negotiatedSMUXConfig(t, xrayConfig(t, false, "vless", serverPort, socksPort, "smux", padding, certificate, ""), padding, "auto")
			writeConfig(t, clientPath, clientConfig)
			client := startE2EProcess(t, xray, "run", "-config", clientPath)
			waitSOCKS(t, client, socksPort)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("client logs:\n%s", client.logs.String())
				}
			})
			if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
				t.Fatalf("legacy fallback: %v", err)
			}
		})
	}
	if !t.Failed() {
		t.Log("SMUX_AUTO_FALLBACK_OK")
	}
}

func buildLegacySMUXServer(t *testing.T, workDir, xrayRoot string) string {
	t.Helper()
	if binary := os.Getenv("XRAY_LEGACY_SMUX_E2E_BIN"); binary != "" {
		return binary
	}
	source := filepath.Join(workDir, "legacy-smux-source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(workDir, "legacy-smux.tar")
	archive := exec.Command("git", "-C", xrayRoot, "archive", "--output", archivePath, legacySMUXServerRevision)
	if output, err := archive.CombinedOutput(); err != nil {
		t.Fatalf("archive legacy Xray %s: %v\n%s", legacySMUXServerRevision, err, output)
	}
	extract := exec.Command("tar", "-xf", archivePath, "-C", source)
	if output, err := extract.CombinedOutput(); err != nil {
		t.Fatalf("extract legacy Xray: %v\n%s", err, output)
	}
	return buildE2EBinary(t, "XRAY_LEGACY_SMUX_E2E_BIN", filepath.Join(workDir, "xray-legacy-smux"), source, "./main", "-buildvcs=false")
}

func negotiatedSMUXConfig(t testing.TB, encoded []byte, padding bool, policy string) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	outbound := config["outbounds"].([]any)[0].(map[string]any)
	outbound["smux"] = map[string]any{"enabled": true, "protocol": "smux", "maxConnections": 1, "padding": padding, "logicalHalfClose": policy}
	result, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return result
}
