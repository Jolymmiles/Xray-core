//go:build integration

package singmux_test

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHysteriaProcessClientMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level Hysteria client interoperability matrix")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	udpEcho := startUDPEcho(t).(*net.UDPAddr)

	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		t.Run(peer, func(t *testing.T) {
			runHysteriaClientScenario(t, workDir, binaries, certificate, privateKey, peer, tcpEcho, udpEcho)
		})
	}
}

func runHysteriaClientScenario(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey, peer string, tcpEcho *net.TCPAddr, udpEcho *net.UDPAddr) {
	t.Helper()
	serverPort := freeUDPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(scenarioDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(scenarioDir, "server.key"))

	serverPath := filepath.Join(scenarioDir, "server.json")
	writeConfig(t, serverPath, xrayHysteriaServerConfig(t, serverPort, certificate, privateKey))
	server := startE2EProcess(t, binaries.xray, "run", "-config", serverPath)

	clientBinary, clientArgs, clientConfig := hysteriaClientConfig(t, binaries, peer, serverPort, socksPort, certificate)
	clientPath := filepath.Join(scenarioDir, "client"+configExtension(peer, peer == "xray"))
	clientArgs = replaceConfigPath(clientArgs, clientPath)
	writeConfig(t, clientPath, clientConfig)
	client := startReadyE2EClient(t, peer, clientBinary, clientArgs, socksPort)
	waitSOCKSTCPForwarding(t, client, socksPort, tcpEcho)

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
			t.Logf("client logs:\n%s", client.logs.String())
		}
	})
	testSOCKSTCP(t, socksPort, tcpEcho)
	testSOCKSUDP(t, socksPort, udpEcho)
}

func xrayHysteriaServerConfig(t testing.TB, port int, certificate, privateKey string) []byte {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "hysteria",
			"settings": map[string]any{
				"version": 2,
				"clients": []any{map[string]any{"auth": testPassword, "email": "e2e@example.test"}},
			},
			"streamSettings": map[string]any{
				"network": "hysteria", "security": "tls",
				"tlsSettings": map[string]any{
					"alpn":         []string{"h3"},
					"certificates": []any{map[string]any{"certificateFile": certificate, "keyFile": privateKey}},
				},
				"finalmask":        map[string]any{"quicParams": map[string]any{"congestion": "bbr"}},
				"hysteriaSettings": map[string]any{"version": 2},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func hysteriaClientConfig(t *testing.T, binaries e2eBinaries, peer string, serverPort, socksPort int, certificate string) (string, []string, []byte) {
	t.Helper()
	switch peer {
	case "xray":
		config := map[string]any{
			"log": map[string]any{"loglevel": "warning"},
			"inbounds": []any{map[string]any{
				"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
			}},
			"outbounds": []any{map[string]any{
				"protocol": "hysteria",
				"settings": map[string]any{"version": 2, "address": "127.0.0.1", "port": serverPort},
				"streamSettings": map[string]any{
					"network": "hysteria", "security": "tls",
					"tlsSettings":      map[string]any{"alpn": []string{"h3"}, "serverName": "localhost", "pinnedPeerCertSha256": certificatePin(certificate)},
					"finalmask":        map[string]any{"quicParams": map[string]any{"congestion": "bbr"}},
					"hysteriaSettings": map[string]any{"version": 2, "auth": testPassword},
				},
			}},
		}
		encoded, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return binaries.xray, []string{"run", "-config", "client.json"}, encoded
	case "sing-box":
		config := map[string]any{
			"log":      map[string]any{"level": "warn"},
			"inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
			"outbounds": []any{map[string]any{
				"type": "hysteria2", "server": "127.0.0.1", "server_port": serverPort,
				"password": testPassword,
				"tls":      map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
			}},
		}
		encoded, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return binaries.singBox, []string{"run", "-c", "client.json"}, encoded
	case "mihomo":
		config := fmt.Sprintf("socks-port: %d\nallow-lan: false\nmode: global\nlog-level: warning\nproxies:\n  - name: hysteria-e2e\n    type: hysteria2\n    server: 127.0.0.1\n    port: %d\n    password: %s\n    sni: localhost\n    alpn:\n      - h3\n    skip-cert-verify: true\nproxy-groups:\n  - name: GLOBAL\n    type: select\n    proxies:\n      - hysteria-e2e\n", socksPort, serverPort, testPassword)
		return binaries.mihomo, []string{"-d", ".", "-f", "client.yaml"}, []byte(config)
	default:
		t.Fatalf("unsupported Hysteria peer %q", peer)
		return "", nil, nil
	}
}

func freeUDPPort(t testing.TB) int {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := connection.LocalAddr().(*net.UDPAddr).Port
	_ = connection.Close()
	return port
}
