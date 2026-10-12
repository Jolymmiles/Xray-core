//go:build integration

package singmux_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkVLESSTCPProcessUserEmail is BenchmarkVLESSTCPProcess with and
// without an email on the server's user: only users with an email can be
// removed, so only their connections are tracked for removal. Every operation
// opens a new VLESS connection. XRAY_E2E_SERVER_BIN runs another Xray as the
// server, such as a baseline build, against the same client.
func BenchmarkVLESSTCPProcessUserEmail(b *testing.B) {
	workDir := b.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		b.Fatal(err)
	}
	client := buildE2EBinary(b, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	server := client
	if path := os.Getenv("XRAY_E2E_SERVER_BIN"); path != "" {
		server = path
	}
	certificate, privateKey := generateCertificate(b, workDir)
	tcpEcho := startTCPEcho(b).(*net.TCPAddr)

	for _, security := range []string{"tls", "reality"} {
		for _, flow := range []string{"", "xtls-rprx-vision"} {
			flowName := "no-flow"
			if flow != "" {
				flowName = "vision"
			}
			for _, email := range []string{"", "bench@example.com"} {
				emailName := "no-email"
				if email != "" {
					emailName = "email"
				}
				b.Run(filepath.Join(security, flowName, emailName), func(b *testing.B) {
					b.StopTimer()
					scenarioDir := b.TempDir()
					serverPort := freeTCPPort(b)
					socksPort := freeTCPUDPPort(b)
					realityTarget := ""
					if security == "reality" {
						realityTarget = startRealityCoverServer(b, certificate, privateKey)
					}
					serverPath := filepath.Join(scenarioDir, "server.json")
					clientPath := filepath.Join(scenarioDir, "client.json")
					serverConfig := xrayVLESSTCPConfig(b, true, serverPort, 0, security, flow, certificate, privateKey, realityTarget)
					writeConfig(b, serverPath, revokeBenchmarkWithEmail(b, serverConfig, email))
					writeConfig(b, clientPath, xrayVLESSTCPConfig(b, false, serverPort, socksPort, security, flow, certificate, "", ""))
					serverProcess := startE2EProcess(b, server, "run", "-config", serverPath)
					waitTCP(b, serverProcess, serverPort)
					clientProcess := startE2EProcess(b, client, "run", "-config", clientPath)
					waitSOCKS(b, clientProcess, socksPort)
					if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
						b.Fatalf("warm-up: %v\nserver logs:\n%s\nclient logs:\n%s", err, serverProcess.logs.String(), clientProcess.logs.String())
					}

					b.ResetTimer()
					b.StartTimer()
					for b.Loop() {
						if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
				})
			}
		}
	}
}

// revokeBenchmarkWithEmail sets email on the only user of a VLESS server
// configuration from xrayVLESSTCPConfig.
func revokeBenchmarkWithEmail(b *testing.B, config []byte, email string) []byte {
	b.Helper()
	if email == "" {
		return config
	}
	var parsed map[string]any
	if err := json.Unmarshal(config, &parsed); err != nil {
		b.Fatal(err)
	}
	inbound := parsed["inbounds"].([]any)[0].(map[string]any)
	user := inbound["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
	user["email"] = email
	encoded, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		b.Fatal(err)
	}
	return encoded
}
