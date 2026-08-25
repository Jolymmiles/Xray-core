//go:build integration

package singmux_test

import (
	"encoding/json"
	"net"
	"os"
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

func TestSMUXAutoFallbackExternalPeers(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level SMUX auto fallback")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	for _, peer := range []string{"sing-box", "mihomo"} {
		for _, padding := range []bool{false, true} {
			t.Run(peer+map[bool]string{false: "/padding=false", true: "/padding=true"}[padding], func(t *testing.T) {
				serverPort, socksPort := freeTCPPort(t), freeTCPPort(t)
				dir := filepath.Join(workDir, t.Name())
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				cert := copyScenarioFile(t, certificate, filepath.Join(dir, "server.crt"))
				key := copyScenarioFile(t, privateKey, filepath.Join(dir, "server.key"))
				serverBinary, serverArgs, serverConfig := peerServerConfig(t, binaries, peer, "vless", serverPort, padding, cert, key)
				serverPath := filepath.Join(dir, "server"+configExtension(peer, false))
				serverArgs = replaceConfigPath(serverArgs, serverPath)
				marker := ""
				if peer == "mihomo" {
					marker = filepath.Join(dir, "ready")
					serverArgs = withMihomoPostUp(serverArgs, marker)
				}
				writeConfig(t, serverPath, serverConfig)
				server := startReadyE2EServer(t, serverBinary, serverArgs, serverPort, marker)
				clientPath := filepath.Join(dir, "client.json")
				clientConfig := negotiatedSMUXConfig(t, xrayConfig(t, false, "vless", serverPort, socksPort, "smux", padding, cert, ""), padding, "auto")
				writeConfig(t, clientPath, clientConfig)
				client := startE2EProcess(t, binaries.xray, "run", "-config", clientPath)
				waitSOCKS(t, client, socksPort)
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("server logs:\n%s", server.logs.String())
						t.Logf("client logs:\n%s", client.logs.String())
					}
				})
				if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
					t.Fatalf("legacy fallback: %v", err)
				}
			})
		}
	}
	if !t.Failed() {
		t.Log("SMUX_AUTO_FALLBACK_OK")
	}
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
