//go:build integration

package singmux_test

import (
	"crypto/ecdh"
	"crypto/rand"
	cryptotls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	realityPrivateKey, realityPublicKey = generateRealityKeyPair()
	realityShortID                      = generateRealityShortID()
)

func generateRealityKeyPair() (string, string) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	encoding := base64.RawURLEncoding
	return encoding.EncodeToString(privateKey.Bytes()), encoding.EncodeToString(privateKey.PublicKey().Bytes())
}

func generateRealityShortID() string {
	shortID := make([]byte, 8)
	if _, err := rand.Read(shortID); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", shortID)
}

func TestVLESSTCPProcessMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level VLESS TCP transport matrix")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t)

	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		for _, security := range []string{"tls", "reality"} {
			for _, flow := range []string{"", "xtls-rprx-vision"} {
				flowName := "no-flow"
				if flow != "" {
					flowName = "vision"
				}
				t.Run(filepath.Join(peer, security, flowName), func(t *testing.T) {
					runVLESSTCPScenario(t, workDir, binaries, certificate, privateKey, peer, security, flow, tcpEcho)
				})
			}
		}
	}
}

func BenchmarkVLESSTCPProcess(b *testing.B) {
	workDir := b.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		b.Fatal(err)
	}
	xray := buildE2EBinary(b, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(b, workDir)
	tcpEcho := startTCPEcho(b).(*net.TCPAddr)

	for _, security := range []string{"tls", "reality"} {
		for _, flow := range []string{"", "xtls-rprx-vision"} {
			flowName := "no-flow"
			if flow != "" {
				flowName = "vision"
			}
			b.Run(filepath.Join(security, flowName), func(b *testing.B) {
				b.StopTimer()
				scenarioDir := b.TempDir()
				serverPort := freeTCPPort(b)
				socksPort := freeTCPPort(b)
				realityTarget := ""
				if security == "reality" {
					realityTarget = startRealityCoverServer(b, certificate, privateKey)
				}
				serverPath := filepath.Join(scenarioDir, "server.json")
				clientPath := filepath.Join(scenarioDir, "client.json")
				writeConfig(b, serverPath, xrayVLESSTCPConfig(b, true, serverPort, 0, security, flow, certificate, privateKey, realityTarget))
				writeConfig(b, clientPath, xrayVLESSTCPConfig(b, false, serverPort, socksPort, security, flow, certificate, "", ""))
				server := startE2EProcess(b, xray, "run", "-config", serverPath)
				waitTCP(b, server, serverPort)
				client := startE2EProcess(b, xray, "run", "-config", clientPath)
				waitSOCKS(b, client, socksPort)
				if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
					b.Fatalf("warm-up: %v\nserver logs:\n%s\nclient logs:\n%s", err, server.logs.String(), client.logs.String())
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

func runVLESSTCPScenario(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey, peer, security, flow string, tcpEcho net.Addr) {
	t.Helper()
	serverPort := freeTCPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, strings.NewReplacer("/", "-", "=", "-").Replace(t.Name()))
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(scenarioDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(scenarioDir, "server.key"))
	realityTarget := ""
	if security == "reality" {
		realityTarget = startRealityCoverServer(t, certificate, privateKey)
	} else if security != "tls" {
		t.Fatalf("unsupported VLESS TCP security %q", security)
	}

	serverPath := filepath.Join(scenarioDir, "server.json")
	writeConfig(t, serverPath, xrayVLESSTCPConfig(t, true, serverPort, 0, security, flow, certificate, privateKey, realityTarget))
	server := startE2EProcess(t, binaries.xray, "run", "-config", serverPath)
	waitTCP(t, server, serverPort)

	clientBinary, clientArgs, clientConfig := vlessTCPClientConfig(t, binaries, peer, serverPort, socksPort, security, flow, certificate)
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
	testSOCKSTCP(t, socksPort, tcpEcho.(*net.TCPAddr))
}

func waitSOCKSTCPForwarding(t *testing.T, process *e2eProcess, socksPort int, destination *net.TCPAddr) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := runSOCKSTCP(socksPort, destination); err == nil {
			return
		} else {
			lastErr = err
		}
		select {
		case processErr := <-process.done:
			t.Fatalf("client exited before forwarding became ready: %v\n%s", processErr, process.logs.String())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("SOCKS forwarding did not become ready: %v\n%s", lastErr, process.logs.String())
}

func startRealityCoverServer(t testing.TB, certificate, privateKey string) string {
	t.Helper()
	pair, err := cryptotls.LoadX509KeyPair(certificate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := cryptotls.Listen("tcp4", "127.0.0.1:0", &cryptotls.Config{
		Certificates: []cryptotls.Certificate{pair},
		MinVersion:   cryptotls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

func xrayVLESSTCPConfig(t testing.TB, server bool, serverPort, socksPort int, security, flow, certificate, privateKey, realityTarget string) []byte {
	t.Helper()
	config := map[string]any{"log": map[string]any{"loglevel": "warning"}}
	user := map[string]any{"id": testUUID}
	if flow != "" {
		user["flow"] = flow
	}
	if server {
		config["inbounds"] = []any{map[string]any{
			"listen": "127.0.0.1", "port": serverPort, "protocol": "vless",
			"settings": map[string]any{"decryption": "none", "clients": []any{user}},
			"sniffing": map[string]any{
				"enabled": true, "destOverride": []string{"http", "tls"},
				"domainsExcluded": []string{`regexp:(^|\.)whatsapp\.com$`},
			},
			"streamSettings": xrayVLESSTCPStreamSettings(true, security, certificate, privateKey, realityTarget),
		}}
		config["outbounds"] = []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}}
	} else {
		config["inbounds"] = []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}}
		config["outbounds"] = []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": serverPort,
				"users": []any{map[string]any{"id": testUUID, "encryption": "none", "flow": flow}},
			}}},
			"streamSettings": xrayVLESSTCPStreamSettings(false, security, certificate, "", ""),
		}}
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func xrayVLESSTCPStreamSettings(server bool, security, certificate, privateKey, realityTarget string) map[string]any {
	if security == "tls" {
		return xrayTLSSettings(server, certificate, privateKey)
	}
	settings := map[string]any{"security": "reality"}
	if server {
		settings["realitySettings"] = map[string]any{
			"show": false, "target": realityTarget, "serverNames": []string{"localhost"},
			"privateKey": realityPrivateKey, "shortIds": []string{realityShortID},
		}
	} else {
		settings["realitySettings"] = map[string]any{
			"show": false, "fingerprint": "chrome", "serverName": "localhost",
			"publicKey": realityPublicKey, "shortId": realityShortID, "spiderX": "/",
		}
	}
	return settings
}

func vlessTCPClientConfig(t *testing.T, binaries e2eBinaries, peer string, serverPort, socksPort int, security, flow, certificate string) (string, []string, []byte) {
	t.Helper()
	switch peer {
	case "xray":
		return binaries.xray, []string{"run", "-config", "client.json"}, xrayVLESSTCPConfig(t, false, serverPort, socksPort, security, flow, certificate, "", "")
	case "sing-box":
		tlsSettings := map[string]any{"enabled": true, "server_name": "localhost", "insecure": true}
		if security == "reality" {
			tlsSettings = map[string]any{
				"enabled": true, "server_name": "localhost",
				"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": realityPublicKey, "short_id": realityShortID},
			}
		}
		outbound := map[string]any{
			"type": "vless", "server": "127.0.0.1", "server_port": serverPort, "uuid": testUUID,
			"tls": tlsSettings,
		}
		if flow != "" {
			outbound["flow"] = flow
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
		flowLine := ""
		if flow != "" {
			flowLine = fmt.Sprintf("    flow: %s\n", flow)
		}
		realityLines := "    skip-cert-verify: true\n"
		if security == "reality" {
			realityLines = fmt.Sprintf("    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: %s\n", realityPublicKey, realityShortID)
		}
		config := fmt.Sprintf("socks-port: %d\nallow-lan: false\nmode: global\nlog-level: debug\nproxies:\n  - name: vless-e2e\n    type: vless\n    server: 127.0.0.1\n    port: %d\n    uuid: %s\n    network: tcp\n    tls: true\n    servername: localhost\n%s%sproxy-groups:\n  - name: GLOBAL\n    type: select\n    proxies:\n      - vless-e2e\n", socksPort, serverPort, testUUID, realityLines, flowLine)
		return binaries.mihomo, []string{"-d", ".", "-f", "client.yaml"}, []byte(config)
	default:
		t.Fatalf("unsupported VLESS TCP peer %q", peer)
		return "", nil, nil
	}
}
