//go:build integration

package singmux_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	statscommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	testUUID          = "b831381d-6324-4d53-ad4f-8cda48b30811"
	testPassword      = "xray-smux-e2e-password"
	testPresenceEmail = "structural-presence@example.com"
)

type e2eBinaries struct {
	xray    string
	singBox string
	mihomo  string
}

type e2eProcess struct {
	command *exec.Cmd
	done    chan error
	logs    synchronizedBuffer
	stopped atomic.Bool
}

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(payload)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestSMUXProcessInteropMatrix(t *testing.T) {
	testMuxProcessInteropMatrix(t, "smux")
}

func TestH2MUXProcessInteropMatrix(t *testing.T) {
	testMuxProcessInteropMatrix(t, "h2mux")
}

func testMuxProcessInteropMatrix(t *testing.T, protocol string) {
	if testing.Short() {
		t.Skip("process-level mux interoperability matrix")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t)
	udpEcho := startUDPEcho(t)

	for _, scenario := range muxInteropScenarios() {
		name := fmt.Sprintf("%s/xray-server/%s/%s/padding=%t", scenario.peer, scenario.carrier, scenario.network, scenario.padding)
		t.Run(name, func(t *testing.T) {
			runInteropScenario(t, workDir, binaries, certificate, privateKey, scenario.peer, scenario.carrier, scenario.network, protocol, scenario.padding, tcpEcho, udpEcho)
		})
	}
}

type muxInteropScenario struct {
	peer, carrier, network string
	padding                bool
}

func muxInteropScenarios() []muxInteropScenario {
	var scenarios []muxInteropScenario
	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		for _, carrier := range []string{"vless", "trojan"} {
			for _, network := range []string{"tcp", "udp"} {
				for _, padding := range []bool{false, true} {
					scenarios = append(scenarios, muxInteropScenario{peer: peer, carrier: carrier, network: network, padding: padding})
				}
			}
		}
	}
	return scenarios
}

func TestStructuredRejectedAccessProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level structured rejection logging")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(t, workDir)

	for _, carrier := range []string{"vless", "trojan"} {
		t.Run(carrier, func(t *testing.T) {
			port := freeTCPPort(t)
			configPath := filepath.Join(workDir, carrier+"-rejected.json")
			writeConfig(t, configPath, xrayConfig(t, true, carrier, port, 0, "smux", false, certificate, privateKey))
			server := startE2EProcess(t, xray, "run", "-config", configPath)
			waitTCP(t, server, port)

			var connection net.Conn
			var err error
			if carrier == "trojan" {
				connection, err = tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- isolated test certificate
			} else {
				connection, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Write(bytes.Repeat([]byte{0xff}, 128)); err != nil {
				_ = connection.Close()
				t.Fatal(err)
			}
			_ = connection.Close()
			waitProcessLog(t, server, `"status":"rejected"`)

			wantComponent := "proxy/" + carrier
			if carrier == "vless" {
				wantComponent += "/inbound"
			}
			for _, line := range strings.Split(server.logs.String(), "\n") {
				var record struct {
					Type      string `json:"type"`
					Status    string `json:"status"`
					Component string `json:"component"`
					Inbound   string `json:"inbound"`
					SessionID uint32 `json:"session_id"`
					Source    string `json:"source"`
					Reason    string `json:"reason"`
				}
				if json.Unmarshal([]byte(line), &record) != nil || record.Status != "rejected" {
					continue
				}
				if record.Type != "access" || record.Component != wantComponent || record.Inbound != "e2e-in" || record.SessionID == 0 || record.Source == "" || record.Reason == "" {
					t.Fatalf("incomplete rejected access record: %+v\nserver logs:\n%s", record, server.logs.String())
				}
				return
			}
			t.Fatalf("missing rejected access record\nserver logs:\n%s", server.logs.String())
		})
	}
}

func buildE2EBinaries(t *testing.T, workDir string) e2eBinaries {
	t.Helper()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	coresRoot := filepath.Dir(xrayRoot)
	if _, err := os.Stat(filepath.Join(coresRoot, "sing-box")); err != nil {
		coresRoot = filepath.Dir(coresRoot)
	}
	return e2eBinaries{
		xray:    buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main"),
		singBox: buildE2EBinary(t, "SING_BOX_E2E_BIN", filepath.Join(workDir, "sing-box"), filepath.Join(coresRoot, "sing-box"), "./cmd/sing-box", "-tags=with_utls,with_quic"),
		mihomo:  buildE2EBinary(t, "MIHOMO_E2E_BIN", filepath.Join(workDir, "mihomo"), filepath.Join(coresRoot, "mihomo"), "."),
	}
}

func buildE2EBinary(t testing.TB, environment, output, directory, target string, buildOptions ...string) string {
	t.Helper()
	if existing := os.Getenv(environment); existing != "" {
		return existing
	}
	arguments := append([]string{"build"}, buildOptions...)
	arguments = append(arguments, "-o", output, target)
	command := exec.Command("go", arguments...)
	command.Dir = directory
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s in %s: %v\n%s", target, directory, err, combined)
	}
	return output
}

func runInteropScenario(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey, peer, carrier, network, protocol string, padding bool, tcpEcho, udpEcho net.Addr) {
	t.Helper()
	serverPort := freeWildcardTCPPort(t)
	socksPort := freeTCPUDPPort(t)
	apiPort := freeTCPPort(t)
	wantOnlineIP := nonLoopbackHostIPv4(t)
	scenarioDir := filepath.Join(workDir, strings.NewReplacer("/", "-", "=", "-").Replace(t.Name()))
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(scenarioDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(scenarioDir, "server.key"))

	serverPath := filepath.Join(scenarioDir, "server.json")
	clientPath := filepath.Join(scenarioDir, "client"+configExtension(peer, false))
	serverConfig := xrayPresenceServerConfig(t, carrier, serverPort, apiPort, protocol, padding, certificate, privateKey)
	clientBinary, clientArgs, clientConfig := peerClientConfig(t, binaries, peer, carrier, serverPort, socksPort, protocol, padding, certificate, wantOnlineIP)
	clientArgs = replaceConfigPath(clientArgs, clientPath)
	writeConfig(t, serverPath, serverConfig)
	writeConfig(t, clientPath, clientConfig)

	server := startReadyE2EServer(t, binaries.xray, []string{"run", "-config", serverPath}, serverPort, "")
	client := startReadyE2EClient(t, peer, clientBinary, clientArgs, socksPort)

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
			t.Logf("client logs:\n%s", client.logs.String())
		}
	})
	statsClient := dialStatsService(t, apiPort)
	assertOnline := func() { waitStatsOnlineIPs(t, statsClient, wantOnlineIP) }
	if network == "tcp" {
		testSOCKSTCP(t, socksPort, tcpEcho.(*net.TCPAddr), assertOnline)
	} else {
		testSOCKSUDP(t, socksPort, udpEcho.(*net.UDPAddr), assertOnline)
	}
	if network == "udp" {
		stopE2EProcess(t, client)
	}
	waitStatsOnlineIPs(t, statsClient)
	assertStructuredAccessDestination(t, server, network, tcpEcho, udpEcho)
}

func configExtension(peer string, xray bool) string {
	if xray || peer == "xray" || peer == "sing-box" {
		return ".json"
	}
	return ".yaml"
}

func replaceConfigPath(arguments []string, path string) []string {
	result := append([]string(nil), arguments...)
	if len(result) == 0 {
		return result
	}
	result[len(result)-1] = path
	if len(result) >= 2 && result[0] == "-d" {
		result[1] = filepath.Dir(path)
	}
	return result
}

func TestMihomoPostUpKeepsConfigFlagPair(t *testing.T) {
	arguments := withMihomoPostUp([]string{"-d", ".", "-f", "server.yaml"}, "/tmp/ready")
	if got, want := strings.Join(arguments, "\x00"), strings.Join([]string{"-d", ".", "-post-up", `echo ready > "/tmp/ready"`, "-f", "server.yaml"}, "\x00"); got != want {
		t.Fatalf("Mihomo arguments = %q, want %q", arguments, want)
	}
}

func withMihomoPostUp(arguments []string, marker string) []string {
	configFlag := len(arguments) - 2
	result := append([]string(nil), arguments[:configFlag]...)
	result = append(result, "-post-up", fmt.Sprintf("echo ready > %q", filepath.ToSlash(marker)))
	result = append(result, arguments[configFlag:]...)
	return result
}

func peerClientConfig(t *testing.T, binaries e2eBinaries, peer, carrier string, serverPort, socksPort int, protocol string, padding bool, certificate string, serverAddresses ...string) (string, []string, []byte) {
	t.Helper()
	serverAddress := "127.0.0.1"
	if len(serverAddresses) != 0 {
		serverAddress = serverAddresses[0]
	}
	if peer == "xray" {
		return binaries.xray, []string{"run", "-config", "client.json"}, xrayConfig(t, false, carrier, serverPort, socksPort, protocol, padding, certificate, "", serverAddress)
	}
	if peer == "sing-box" {
		return binaries.singBox, []string{"run", "-c", "client.json"}, singBoxClientConfig(t, carrier, serverPort, socksPort, protocol, padding, serverAddress)
	}
	return binaries.mihomo, []string{"-d", ".", "-f", "client.yaml"}, mihomoClientConfig(carrier, serverPort, socksPort, protocol, padding, serverAddress)
}

func xrayConfig(t *testing.T, server bool, carrier string, serverPort, socksPort int, protocol string, padding bool, certificate, privateKey string, serverAddresses ...string) []byte {
	t.Helper()
	serverAddress := "127.0.0.1"
	if len(serverAddresses) != 0 {
		serverAddress = serverAddresses[0]
	}
	config := map[string]any{"log": map[string]any{"loglevel": "debug"}}
	if server {
		config["log"] = map[string]any{
			"loglevel": "warning",
			"outputs": []any{map[string]any{
				"name": "access-e2e", "type": "console", "stream": "stdout",
				"events": []string{"access"}, "format": "json", "color": "never",
				"level": "info", "backpressure": "sync", "maxRecordSize": 65536,
			}},
		}
		inboundSettings := map[string]any{}
		if carrier == "vless" {
			inboundSettings = map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": testUUID}}}
		} else {
			inboundSettings = map[string]any{"clients": []any{map[string]any{"password": testPassword}}}
		}
		inbound := map[string]any{"tag": "e2e-in", "listen": "127.0.0.1", "port": serverPort, "protocol": carrier, "settings": inboundSettings}
		if carrier == "trojan" {
			inbound["streamSettings"] = xrayTLSSettings(true, certificate, privateKey)
		}
		config["inbounds"] = []any{inbound}
		config["outbounds"] = []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}}
	} else {
		config["inbounds"] = []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		}}
		var settings map[string]any
		if carrier == "vless" {
			settings = map[string]any{"vnext": []any{map[string]any{
				"address": serverAddress, "port": serverPort,
				"users": []any{map[string]any{"id": testUUID, "encryption": "none"}},
			}}}
		} else {
			settings = map[string]any{"servers": []any{map[string]any{
				"address": serverAddress, "port": serverPort, "password": testPassword,
			}}}
		}
		outbound := map[string]any{
			"protocol": carrier,
			"settings": settings,
			"smux":     map[string]any{"enabled": true, "protocol": protocol, "maxConnections": 1, "padding": padding},
		}
		if carrier == "trojan" {
			outbound["streamSettings"] = xrayTLSSettings(false, certificate, "")
		}
		config["outbounds"] = []any{outbound}
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func xrayPresenceServerConfig(t *testing.T, carrier string, serverPort, apiPort int, protocol string, padding bool, certificate, privateKey string) []byte {
	t.Helper()
	encoded := xrayConfig(t, true, carrier, serverPort, 0, protocol, padding, certificate, privateKey)
	var config map[string]any
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	inbound := inbounds[0].(map[string]any)
	inbound["listen"] = "0.0.0.0"
	settings := inbound["settings"].(map[string]any)
	clients := settings["clients"].([]any)
	clients[0].(map[string]any)["email"] = testPresenceEmail
	config["stats"] = map[string]any{}
	config["policy"] = map[string]any{"levels": map[string]any{
		"0": map[string]any{"statsUserOnline": true},
	}}
	config["api"] = map[string]any{
		"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", apiPort), "services": []string{"StatsService"},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertStructuredAccessDestination(t *testing.T, process *e2eProcess, network string, tcpEcho, udpEcho net.Addr) {
	t.Helper()
	waitProcessLog(t, process, `"type":"access"`)
	wantDestination := network + ":"
	if network == "tcp" {
		wantDestination += tcpEcho.String()
	} else {
		wantDestination += udpEcho.String()
	}
	var acceptedDestinations []string
	for _, line := range strings.Split(process.logs.String(), "\n") {
		var record struct {
			Type        string `json:"type"`
			Status      string `json:"status"`
			Destination string `json:"destination"`
		}
		if json.Unmarshal([]byte(line), &record) != nil || record.Type != "access" || record.Status != "accepted" {
			continue
		}
		acceptedDestinations = append(acceptedDestinations, record.Destination)
		if record.Destination == "tcp:sp.mux.sing-box.arpa:444" {
			t.Fatalf("structured access log exposed the SMUX carrier instead of its logical stream: %s", line)
		}
		if record.Destination == wantDestination {
			return
		}
	}
	t.Fatalf("missing structured access destination %q; accepted destinations=%q\nserver logs:\n%s", wantDestination, acceptedDestinations, process.logs.String())
}

func xrayTLSSettings(server bool, certificate, privateKey string) map[string]any {
	settings := map[string]any{"security": "tls"}
	if server {
		settings["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{
			"certificateFile": certificate, "keyFile": privateKey,
		}}}
	} else {
		settings["tlsSettings"] = map[string]any{
			"pinnedPeerCertSha256": certificatePin(certificate),
			"serverName":           "localhost",
		}
	}
	return settings
}

func singBoxClientConfig(t *testing.T, carrier string, serverPort, socksPort int, protocol string, padding bool, serverAddresses ...string) []byte {
	t.Helper()
	serverAddress := "127.0.0.1"
	if len(serverAddresses) != 0 {
		serverAddress = serverAddresses[0]
	}
	config := map[string]any{"log": map[string]any{"level": "debug", "timestamp": true}}
	config["inbounds"] = []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort}}
	outbound := map[string]any{
		"type": carrier, "server": serverAddress, "server_port": serverPort,
		"multiplex": map[string]any{"enabled": true, "protocol": protocol, "max_connections": 1, "padding": padding},
	}
	if carrier == "vless" {
		outbound["uuid"] = testUUID
		packetEncoding := "packetaddr"
		outbound["packet_encoding"] = packetEncoding
	} else {
		outbound["password"] = testPassword
		outbound["tls"] = map[string]any{"enabled": true, "server_name": "localhost", "insecure": true}
	}
	config["outbounds"] = []any{outbound}

	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mihomoClientConfig(carrier string, serverPort, socksPort int, protocol string, padding bool, serverAddresses ...string) []byte {
	serverAddress := "127.0.0.1"
	if len(serverAddresses) != 0 {
		serverAddress = serverAddresses[0]
	}
	credentials := fmt.Sprintf("    uuid: %s\n    udp: true\n", testUUID)
	tls := "    tls: false\n"
	if carrier == "trojan" {
		credentials = fmt.Sprintf("    password: %s\n    udp: true\n", testPassword)
		tls = "    tls: true\n    servername: localhost\n    skip-cert-verify: true\n"
	}
	return []byte(fmt.Sprintf("socks-port: %d\nallow-lan: false\nmode: global\nlog-level: warning\nproxies:\n  - name: e2e-peer\n    type: %s\n    server: %s\n    port: %d\n%s%s    smux:\n      enabled: true\n      protocol: %s\n      max-connections: 1\n      padding: %t\nproxy-groups:\n  - name: GLOBAL\n    type: select\n    proxies:\n      - e2e-peer\n", socksPort, carrier, serverAddress, serverPort, credentials, tls, protocol, padding))
}

func writeConfig(t testing.TB, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyScenarioFile(t *testing.T, source, destination string) string {
	t.Helper()
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return destination
}

func startE2EProcess(t testing.TB, binary string, arguments ...string) *e2eProcess {
	t.Helper()
	process := &e2eProcess{command: exec.Command(binary, arguments...), done: make(chan error, 1)}
	process.command.Stdout = &process.logs
	process.command.Stderr = &process.logs
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { process.done <- process.command.Wait() }()
	t.Cleanup(func() {
		if process.stopped.Load() || process.command.ProcessState != nil && process.command.ProcessState.Exited() {
			return
		}
		if process.command.Process != nil {
			_ = process.command.Process.Kill()
		}
		select {
		case <-process.done:
			process.stopped.Store(true)
		case <-time.After(3 * time.Second):
			t.Errorf("process %s did not exit", binary)
		}
	})
	return process
}

func startReadyE2EClient(t testing.TB, peer, binary string, arguments []string, socksPort int) *e2eProcess {
	t.Helper()
	readyMarker := ""
	if peer == "mihomo" {
		readyMarker = filepath.Join(t.TempDir(), "client-ready")
		arguments = withMihomoPostUp(arguments, readyMarker)
	}
	process := startE2EProcess(t, binary, arguments...)
	if readyMarker != "" {
		// Mihomo's parse-complete log precedes provider loading and OnRunning.
		// Its post-up command executes only after ApplyConfig has returned.
		waitProcessFile(t, process, readyMarker)
	}
	waitSOCKS(t, process, socksPort)
	return process
}

func startReadyE2EServer(t testing.TB, binary string, arguments []string, port int, readyMarker string) *e2eProcess {
	t.Helper()
	if readyMarker != "" {
		if err := os.Remove(readyMarker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	process := startE2EProcess(t, binary, arguments...)
	if readyMarker != "" {
		waitProcessFile(t, process, readyMarker)
	}
	waitTCP(t, process, port)
	return process
}

func stopE2EProcess(t testing.TB, process *e2eProcess) {
	t.Helper()
	if process.stopped.Load() || process.command.ProcessState != nil && process.command.ProcessState.Exited() {
		process.stopped.Store(true)
		return
	}
	if process.command.Process != nil {
		_ = process.command.Process.Kill()
	}
	select {
	case <-process.done:
		process.stopped.Store(true)
	case <-time.After(3 * time.Second):
		t.Fatalf("process %s did not stop", process.command.Path)
	}
}

func certificatePin(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		panic("invalid PEM certificate")
	}
	digest := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(digest[:])
}

func waitTCP(t testing.TB, process *e2eProcess, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			if tcpConnection, ok := connection.(*net.TCPConn); ok {
				err = tcpConnection.CloseWrite()
				if err == nil {
					_, readErr := io.Copy(io.Discard, tcpConnection)
					if networkErr, ok := readErr.(net.Error); ok && networkErr.Timeout() {
						err = readErr
					}
				}
			}
			_ = connection.Close()
			if err == nil {
				return
			}
		}
		select {
		case processErr := <-process.done:
			t.Fatalf("process exited before listening on %s: %v\n%s", address, processErr, process.logs.String())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("process did not listen on %s\n%s", address, process.logs.String())
}

func TestWaitTCPDrainsProbe(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	drained := make(chan struct{})
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			return
		}
		_, _ = io.Copy(io.Discard, connection)
		time.Sleep(100 * time.Millisecond)
		close(drained)
		_ = connection.Close()
	}()

	waitTCP(t, &e2eProcess{done: make(chan error)}, listener.Addr().(*net.TCPAddr).Port)
	select {
	case <-drained:
	default:
		t.Fatal("TCP readiness probe returned before the server drained it")
	}
}

func waitProcessLog(t *testing.T, process *e2eProcess, marker string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(process.logs.String(), marker) {
			return
		}
		select {
		case processErr := <-process.done:
			t.Fatalf("process exited before logging %q: %v\n%s", marker, processErr, process.logs.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process did not log %q\n%s", marker, process.logs.String())
}

func waitProcessFile(t testing.TB, process *e2eProcess, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case processErr := <-process.done:
			t.Fatalf("process exited before creating readiness marker %s: %v\n%s", path, processErr, process.logs.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process did not create readiness marker %s\n%s", path, process.logs.String())
}

func waitSOCKS(t testing.TB, process *e2eProcess, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	var lastErr error
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(200 * time.Millisecond))
			err = socksGreeting(connection)
			_ = connection.Close()
			if err == nil {
				return
			}
		}
		lastErr = err
		select {
		case processErr := <-process.done:
			t.Fatalf("process exited before SOCKS readiness on %s: %v\n%s", address, processErr, process.logs.String())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("SOCKS endpoint did not become ready on %s: %v\n%s", address, lastErr, process.logs.String())
}

func TestFreeTCPUDPPortCanBindBothTransports(t *testing.T) {
	port := freeTCPUDPPort(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
}

func freeTCPUDPPort(t testing.TB) int {
	t.Helper()
	for {
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		_ = udp.Close()
		if err != nil {
			continue
		}
		_ = tcp.Close()
		return port
	}
}

func freeWildcardTCPPort(t testing.TB) int {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func freeTCPPort(t testing.TB) int {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func startTCPEcho(t testing.TB) net.Addr {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener.Addr()
}

func startUDPEcho(t *testing.T) net.Addr {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		payload := make([]byte, 65535)
		for {
			n, address, err := connection.ReadFromUDP(payload)
			if err != nil {
				return
			}
			_, _ = connection.WriteToUDP(payload[:n], address)
		}
	}()
	return connection.LocalAddr()
}

func testSOCKSTCP(t *testing.T, socksPort int, destination *net.TCPAddr, callbacks ...func()) {
	t.Helper()
	var afterEcho func()
	if len(callbacks) != 0 {
		afterEcho = callbacks[0]
	}
	if err := runSOCKSTCPWithCallback(socksPort, destination, afterEcho); err != nil {
		t.Fatal(err)
	}
}

func runSOCKSTCP(socksPort int, destination *net.TCPAddr) error {
	return runSOCKSTCPWithCallback(socksPort, destination, nil)
}

func runSOCKSTCPWithCallback(socksPort int, destination *net.TCPAddr, afterEcho func()) error {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial SOCKS: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := socksGreeting(connection); err != nil {
		return fmt.Errorf("SOCKS greeting: %w", err)
	}
	request := append([]byte{5, 1, 0, 1}, destination.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(destination.Port))
	if _, err := connection.Write(request); err != nil {
		return fmt.Errorf("SOCKS connect request: %w", err)
	}
	if err := readSOCKSReply(connection); err != nil {
		return fmt.Errorf("SOCKS connect reply: %w", err)
	}
	payload := []byte("xray-smux-process-tcp")
	if _, err := connection.Write(payload); err != nil {
		return fmt.Errorf("write echo payload: %w", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		return fmt.Errorf("read echo payload: %w", err)
	}
	if !bytes.Equal(response, payload) {
		return fmt.Errorf("TCP response = %q, want %q", response, payload)
	}
	if afterEcho != nil {
		afterEcho()
	}
	return nil
}

func testSOCKSUDP(t *testing.T, socksPort int, destination *net.UDPAddr, callbacks ...func()) {
	t.Helper()
	var afterEcho func()
	if len(callbacks) != 0 {
		afterEcho = callbacks[0]
	}
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	if err := socksGreeting(control); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	relay, err := readSOCKSReplyAddress(control)
	if err != nil {
		t.Fatal(err)
	}
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("xray-smux-process-udp")
	packet := append([]byte{0, 0, 0, 1}, destination.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(destination.Port))
	packet = append(packet, payload...)
	if _, err := udp.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 65535)
	n, _, err := udp.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := socksAddressLength(response[:n], 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response[offset:n], payload) {
		t.Fatalf("UDP response = %q, want %q", response[offset:n], payload)
	}
	if afterEcho != nil {
		afterEcho()
	}
}

func nonLoopbackHostIPv4(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}
	t.Skip("structural presence interop requires a non-loopback IPv4 address")
	return ""
}

func dialStatsService(t *testing.T, port int) statscommand.StatsServiceClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return statscommand.NewStatsServiceClient(connection)
}

func waitStatsOnlineIPs(t *testing.T, client statscommand.StatsServiceClient, want ...string) {
	t.Helper()
	const metric = "user>>>" + testPresenceEmail + ">>>online"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.GetStatsOnlineIpList(context.Background(), &statscommand.GetStatsRequest{Name: metric})
		if err == nil && sameOnlineIPs(response.Ips, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, err := client.GetStatsOnlineIpList(context.Background(), &statscommand.GetStatsRequest{Name: metric})
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("StatsService online IPs = %v, want %v", response.Ips, want)
}

func sameOnlineIPs(got map[string]int64, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, ip := range want {
		if _, found := got[ip]; !found {
			return false
		}
	}
	return true
}

func socksGreeting(connection net.Conn) error {
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if response[0] != 5 || response[1] != 0 {
		return fmt.Errorf("SOCKS greeting response: %x", response)
	}
	return nil
}

func readSOCKSReply(connection net.Conn) error {
	_, err := readSOCKSReplyAddress(connection)
	return err
}

func readSOCKSReplyAddress(connection net.Conn) (*net.UDPAddr, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 {
		return nil, fmt.Errorf("SOCKS reply: %x", header)
	}
	var ip net.IP
	switch header[3] {
	case 1:
		ip = make([]byte, 4)
	case 4:
		ip = make([]byte, 16)
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return nil, err
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(connection, domain); err != nil {
			return nil, err
		}
		resolved, err := net.ResolveIPAddr("ip", string(domain))
		if err != nil {
			return nil, err
		}
		ip = resolved.IP
	default:
		return nil, fmt.Errorf("SOCKS address family: %d", header[3])
	}
	if header[3] != 3 {
		if _, err := io.ReadFull(connection, ip); err != nil {
			return nil, err
		}
	}
	var encodedPort [2]byte
	if _, err := io.ReadFull(connection, encodedPort[:]); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(encodedPort[:]))}, nil
}

func socksAddressLength(packet []byte, offset int) (int, error) {
	if len(packet) <= offset {
		return 0, io.ErrUnexpectedEOF
	}
	switch packet[offset] {
	case 1:
		offset += 1 + 4 + 2
	case 4:
		offset += 1 + 16 + 2
	case 3:
		if len(packet) <= offset+1 {
			return 0, io.ErrUnexpectedEOF
		}
		offset += 1 + 1 + int(packet[offset+1]) + 2
	default:
		return 0, fmt.Errorf("SOCKS datagram address family: %d", packet[offset])
	}
	if len(packet) < offset {
		return 0, io.ErrUnexpectedEOF
	}
	return offset, nil
}

func generateCertificate(t testing.TB, directory string) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "server.crt")
	privateKeyPath := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, privateKeyPath
}

func TestIntegrationPlatform(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Log("Linux is the release-gate platform; interface counter checks run in the stress suite")
	}
}
