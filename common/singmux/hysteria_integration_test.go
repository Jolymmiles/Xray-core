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

// hysteriaGeckoPassword keys the Gecko obfuscation (Hysteria v2.9.2) in the
// gecko cells; Xray configures it as the salamander mask with a packetSize.
const hysteriaGeckoPassword = "e2e-gecko-password"

func TestHysteriaProcessClientMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level Hysteria client interoperability matrix")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	udpEcho := startUDPEcho(t).(*net.UDPAddr)

	for _, obfs := range []string{"plain", "gecko"} {
		for _, peer := range []string{"xray", "sing-box", "mihomo"} {
			t.Run(obfs+"/"+peer, func(t *testing.T) {
				runHysteriaClientScenario(t, workDir, binaries, certificate, privateKey, peer, obfs == "gecko", tcpEcho, udpEcho)
			})
		}
	}
}

func runHysteriaClientScenario(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey, peer string, gecko bool, tcpEcho *net.TCPAddr, udpEcho *net.UDPAddr) {
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
	writeConfig(t, serverPath, xrayHysteriaServerConfig(t, serverPort, certificate, privateKey, gecko))
	server := startE2EProcess(t, binaries.xray, "run", "-config", serverPath)

	clientBinary, clientArgs, clientConfig := hysteriaClientConfig(t, binaries, peer, serverPort, socksPort, certificate, gecko)
	clientPath := filepath.Join(scenarioDir, "client"+configExtension(peer, peer == "xray"))
	clientArgs = replaceConfigPath(clientArgs, clientPath)
	writeConfig(t, clientPath, clientConfig)
	client := startReadyE2EClient(t, peer, clientBinary, clientArgs, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
			t.Logf("client logs:\n%s", client.logs.String())
		}
	})

	waitSOCKSTCPForwarding(t, client, socksPort, tcpEcho)
	testSOCKSTCP(t, socksPort, tcpEcho)
	testSOCKSUDP(t, socksPort, udpEcho)
}

// hysteriaFinalmask is the finalmask of both Xray ends; gecko adds the Gecko
// obfuscation as a UDP mask.
func hysteriaFinalmask(gecko bool) map[string]any {
	finalmask := map[string]any{"quicParams": map[string]any{"congestion": "bbr"}}
	if gecko {
		finalmask["udp"] = []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": hysteriaGeckoPassword, "packetSize": "512-1200"}}}
	}
	return finalmask
}

func xrayHysteriaServerConfig(t testing.TB, port int, certificate, privateKey string, gecko bool) []byte {
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
				"finalmask":        hysteriaFinalmask(gecko),
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

func hysteriaClientConfig(t *testing.T, binaries e2eBinaries, peer string, serverPort, socksPort int, certificate string, gecko bool) (string, []string, []byte) {
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
					"finalmask":        hysteriaFinalmask(gecko),
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
		outbound := map[string]any{
			"type": "hysteria2", "server": "127.0.0.1", "server_port": serverPort,
			"password": testPassword,
			"tls":      map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
		}
		if gecko {
			outbound["obfs"] = map[string]any{"type": "gecko", "password": hysteriaGeckoPassword, "min_packet_size": 512, "max_packet_size": 1200}
		}
		config := map[string]any{
			"log":       map[string]any{"level": "warn"},
			"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
			"outbounds": []any{outbound},
		}
		encoded, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return binaries.singBox, []string{"run", "-c", "client.json"}, encoded
	case "mihomo":
		obfs := ""
		if gecko {
			obfs = fmt.Sprintf("    obfs: gecko\n    obfs-password: %s\n    obfs-min-packet-size: 512\n    obfs-max-packet-size: 1200\n", hysteriaGeckoPassword)
		}
		config := fmt.Sprintf("socks-port: %d\nallow-lan: false\nmode: global\nlog-level: warning\nproxies:\n  - name: hysteria-e2e\n    type: hysteria2\n    server: 127.0.0.1\n    port: %d\n    password: %s\n%s    sni: localhost\n    alpn:\n      - h3\n    skip-cert-verify: true\nproxy-groups:\n  - name: GLOBAL\n    type: select\n    proxies:\n      - hysteria-e2e\n", socksPort, serverPort, testPassword, obfs)
		return binaries.mihomo, []string{"-d", ".", "-f", "client.yaml"}, []byte(config)
	default:
		t.Fatalf("unsupported Hysteria peer %q", peer)
		return "", nil, nil
	}
}
