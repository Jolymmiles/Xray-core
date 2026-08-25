//go:build integration

package singmux_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

const tcpHalfClosePassword = "xray-half-close-password"

func TestTCPHalfCloseProcessMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level TCP half-close matrix")
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
	for _, protocol := range []string{"freedom", "vless", "trojan", "vmess", "shadowsocks", "socks", "http"} {
		t.Run(protocol, func(t *testing.T) {
			runTCPHalfCloseProtocol(t, workDir, xray, certificate, privateKey, protocol, destination, tcpEcho)
		})
	}
	if !t.Failed() {
		t.Log("TCP_HALF_CLOSE_MATRIX_OK")
	}
}

func runTCPHalfCloseProtocol(t *testing.T, workDir, xray, certificate, privateKey, protocol string, destination, tcpEcho *net.TCPAddr) {
	t.Helper()
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, "tcp-half-close-"+protocol)
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(scenarioDir, "client.json")
	var server *e2eProcess
	if protocol == "freedom" {
		writeConfig(t, clientPath, tcpHalfCloseDirectConfig(t, socksPort))
	} else {
		serverPort := freeTCPPort(t)
		serverPath := filepath.Join(scenarioDir, "server.json")
		writeConfig(t, serverPath, tcpHalfCloseServerConfig(t, protocol, serverPort, certificate, privateKey))
		writeConfig(t, clientPath, tcpHalfCloseClientConfig(t, protocol, serverPort, socksPort, certificate))
		server = startE2EProcess(t, xray, "run", "-config", serverPath)
		waitTCP(t, server, serverPort)
	}
	client := startE2EProcess(t, xray, "run", "-config", clientPath)
	waitSOCKS(t, client, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			if server != nil {
				t.Logf("server logs:\n%s", server.logs.String())
			}
			t.Logf("client logs:\n%s", client.logs.String())
		}
	})
	if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
		t.Fatalf("full-path readiness: %v", err)
	}
	if err := runShortSOCKSRequest(socksPort, destination, 10, false); err != nil {
		t.Fatalf("response-side EOF: %v", err)
	}
	if err := runShortSOCKSRequest(socksPort, destination, 11, true); err != nil {
		t.Fatalf("half-close response: %v", err)
	}
	if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
		t.Fatalf("follow-up connection: %v", err)
	}
}

func tcpHalfCloseDirectConfig(t testing.TB, socksPort int) []byte {
	t.Helper()
	return marshalTCPHalfCloseConfig(t, map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{tcpHalfCloseSOCKSInbound(socksPort)},
		"outbounds": []any{tcpHalfCloseFreedomOutbound()},
	})
}

func tcpHalfCloseServerConfig(t testing.TB, protocol string, serverPort int, certificate, privateKey string) []byte {
	t.Helper()
	inbound := map[string]any{"listen": "127.0.0.1", "port": serverPort, "protocol": protocol}
	switch protocol {
	case "vless":
		inbound["settings"] = map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": testUUID}}}
	case "trojan":
		inbound["settings"] = map[string]any{"clients": []any{map[string]any{"password": tcpHalfClosePassword}}}
		inbound["streamSettings"] = xrayTLSSettings(true, certificate, privateKey)
	case "vmess":
		inbound["settings"] = map[string]any{"clients": []any{map[string]any{"id": testUUID}}}
	case "shadowsocks":
		inbound["settings"] = map[string]any{"method": "aes-128-gcm", "password": tcpHalfClosePassword, "network": "tcp"}
	case "socks":
		inbound["settings"] = map[string]any{"auth": "noauth", "udp": false}
	case "http":
		inbound["settings"] = map[string]any{}
	default:
		t.Fatalf("unsupported half-close protocol %q", protocol)
	}
	return marshalTCPHalfCloseConfig(t, map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{inbound},
		"outbounds": []any{tcpHalfCloseFreedomOutbound()},
	})
}

func tcpHalfCloseClientConfig(t testing.TB, protocol string, serverPort, socksPort int, certificate string) []byte {
	t.Helper()
	outbound := map[string]any{"protocol": protocol}
	switch protocol {
	case "vless":
		outbound["settings"] = map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": serverPort, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}
	case "trojan":
		outbound["settings"] = map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": serverPort, "password": tcpHalfClosePassword}}}
		outbound["streamSettings"] = xrayTLSSettings(false, certificate, "")
	case "vmess":
		outbound["settings"] = map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": serverPort, "users": []any{map[string]any{"id": testUUID}}}}}
	case "shadowsocks":
		outbound["settings"] = map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": serverPort, "method": "aes-128-gcm", "password": tcpHalfClosePassword}}}
	case "socks", "http":
		outbound["settings"] = map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": serverPort}}}
	default:
		t.Fatalf("unsupported half-close protocol %q", protocol)
	}
	return marshalTCPHalfCloseConfig(t, map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{tcpHalfCloseSOCKSInbound(socksPort)},
		"outbounds": []any{outbound},
	})
}

func tcpHalfCloseSOCKSInbound(port int) map[string]any {
	return map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}
}

func tcpHalfCloseFreedomOutbound() map[string]any {
	return map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}}}
}

func marshalTCPHalfCloseConfig(t testing.TB, config map[string]any) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
