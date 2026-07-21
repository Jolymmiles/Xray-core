//go:build integration

package kcp_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const mkcpE2EUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

type mkcpE2EProcess struct {
	command *exec.Cmd
	done    chan struct{}
	logs    mkcpSynchronizedBuffer

	mu      sync.Mutex
	exitErr error
}

type mkcpSynchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *mkcpSynchronizedBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(payload)
}

func (b *mkcpSynchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestMKCPProcessE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level mKCP end-to-end test")
	}

	workDir := t.TempDir()
	xray := buildMKCPE2EBinary(t, workDir)
	tcpEcho := startMKCPTCPEcho(t)
	udpEcho := startMKCPUDPEcho(t)

	profiles := []struct {
		name     string
		settings map[string]any
	}{
		{name: "defaults"},
		{
			name: "tuned",
			settings: map[string]any{
				"mtu":              1200,
				"tti":              20,
				"uplinkCapacity":   10,
				"downlinkCapacity": 10,
				"cwndMultiplier":   20,
				"maxSendingWindow": 1024 * 1024,
			},
		},
	}

	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			runMKCPE2EProfile(t, workDir, xray, profile.settings, tcpEcho, udpEcho)
		})
	}
}

func TestMKCPMihomoClientInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level Mihomo mKCP interoperability test")
	}

	workDir := t.TempDir()
	xray := buildMKCPE2EBinary(t, workDir)
	mihomo := buildMKCPMihomoE2EBinary(t, workDir)
	tcpEcho := startMKCPTCPEcho(t)
	udpEcho := startMKCPUDPEcho(t)
	serverPort := freeMKCPUDPPort(t)
	socksPort := freeMKCPTCPPort(t)
	scenarioDir := filepath.Join(workDir, t.Name())
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}

	serverConfig := filepath.Join(scenarioDir, "server.json")
	clientConfig := filepath.Join(scenarioDir, "client.yaml")
	writeMKCPConfig(t, serverConfig, mkcpVMessServerConfig(serverPort))
	if err := os.WriteFile(clientConfig, mkcpMihomoClientConfig(serverPort, socksPort), 0o600); err != nil {
		t.Fatal(err)
	}

	server := startMKCPE2EProcess(t, xray, "run", "-config", serverConfig)
	client := startMKCPE2EProcess(t, mihomo, "-d", scenarioDir, "-f", clientConfig)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("mKCP Xray server logs:\n%s", server.logs.String())
			t.Logf("mKCP Mihomo client logs:\n%s", client.logs.String())
		}
	})

	waitMKCPForwarding(t, server, client, socksPort, tcpEcho)

	t.Run("tcp", func(t *testing.T) {
		payload := bytes.Repeat([]byte("mihomo-xray-mkcp-tcp-"), 12*1024)
		if err := runMKCPSOCKSTCP(socksPort, tcpEcho, payload, 20*time.Second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("udp", func(t *testing.T) {
		payload := bytes.Repeat([]byte("mihomo-xray-mkcp-udp-"), 192)
		if err := runMKCPSOCKSUDP(socksPort, udpEcho, payload); err != nil {
			t.Fatal(err)
		}
	})
}

func runMKCPE2EProfile(t *testing.T, workDir, xray string, settings map[string]any, tcpEcho *net.TCPAddr, udpEcho *net.UDPAddr) {
	t.Helper()

	serverPort := freeMKCPUDPPort(t)
	socksPort := freeMKCPTCPPort(t)
	scenarioDir := filepath.Join(workDir, t.Name())
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}

	serverConfig := filepath.Join(scenarioDir, "server.json")
	clientConfig := filepath.Join(scenarioDir, "client.json")
	writeMKCPConfig(t, serverConfig, mkcpServerConfig(serverPort, settings))
	writeMKCPConfig(t, clientConfig, mkcpClientConfig(serverPort, socksPort, settings))

	server := startMKCPE2EProcess(t, xray, "run", "-config", serverConfig)
	client := startMKCPE2EProcess(t, xray, "run", "-config", clientConfig)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("mKCP server logs:\n%s", server.logs.String())
			t.Logf("mKCP client logs:\n%s", client.logs.String())
		}
	})

	waitMKCPForwarding(t, server, client, socksPort, tcpEcho)

	t.Run("tcp", func(t *testing.T) {
		payload := bytes.Repeat([]byte("xray-mkcp-process-tcp-"), 12*1024)
		if err := runMKCPSOCKSTCP(socksPort, tcpEcho, payload, 20*time.Second); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("udp", func(t *testing.T) {
		payload := bytes.Repeat([]byte("xray-mkcp-process-udp-"), 192)
		if err := runMKCPSOCKSUDP(socksPort, udpEcho, payload); err != nil {
			t.Fatal(err)
		}
	})
}

func mkcpServerConfig(serverPort int, settings map[string]any) map[string]any {
	return map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"tag":      "VLESS-KCP-E2E",
			"listen":   "127.0.0.1",
			"port":     serverPort,
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": mkcpE2EUUID}},
			},
			"sniffing": map[string]any{
				"enabled":      true,
				"routeOnly":    false,
				"destOverride": []string{"http", "tls", "quic"},
			},
			"streamSettings": mkcpStreamSettings(settings),
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{
				"finalRules": []any{map[string]any{"action": "allow"}},
			},
		}},
	}
}

func mkcpVMessServerConfig(serverPort int) map[string]any {
	streamSettings := mkcpStreamSettings(nil)
	streamSettings["finalmask"] = map[string]any{
		"udp": []any{map[string]any{"type": "mkcp-legacy"}},
	}

	return map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"tag":      "VMESS-KCP-E2E",
			"listen":   "127.0.0.1",
			"port":     serverPort,
			"protocol": "vmess",
			"settings": map[string]any{
				"clients": []any{map[string]any{"id": mkcpE2EUUID}},
			},
			"streamSettings": streamSettings,
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{
				"finalRules": []any{map[string]any{"action": "allow"}},
			},
		}},
	}
}

func mkcpMihomoClientConfig(serverPort, socksPort int) []byte {
	return []byte(fmt.Sprintf(`socks-port: %d
allow-lan: false
mode: global
log-level: debug
proxies:
  - name: xray-mkcp
    type: vmess
    server: 127.0.0.1
    port: %d
    uuid: %s
    alterId: 0
    cipher: auto
    udp: true
    network: mkcp
    mkcp-opts:
      mtu: 1350
      tti: 50
      uplink-capacity: 5
      downlink-capacity: 20
      congestion: false
      write-buffer: 2097152
      read-buffer: 2097152
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - xray-mkcp
`, socksPort, serverPort, mkcpE2EUUID))
}

func mkcpClientConfig(serverPort, socksPort int, settings map[string]any) map[string]any {
	return map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     socksPort,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []any{map[string]any{
					"address": "127.0.0.1",
					"port":    serverPort,
					"users":   []any{map[string]any{"id": mkcpE2EUUID, "encryption": "none"}},
				}},
			},
			"streamSettings": mkcpStreamSettings(settings),
		}},
	}
}

func mkcpStreamSettings(settings map[string]any) map[string]any {
	stream := map[string]any{"network": "kcp", "security": "none"}
	if settings != nil {
		stream["kcpSettings"] = settings
	}
	return stream
}

func writeMKCPConfig(t *testing.T, path string, config map[string]any) {
	t.Helper()
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func buildMKCPE2EBinary(t *testing.T, workDir string) string {
	t.Helper()
	if existing := os.Getenv("XRAY_E2E_BIN"); existing != "" {
		return existing
	}

	repository := mkcpRepositoryRoot(t)
	output := filepath.Join(workDir, "xray")
	command := exec.Command("go", "build", "-o", output, "./main")
	command.Dir = repository
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build Xray: %v\n%s", err, combined)
	}
	return output
}

func buildMKCPMihomoE2EBinary(t *testing.T, workDir string) string {
	t.Helper()
	if existing := os.Getenv("MIHOMO_E2E_BIN"); existing != "" {
		return existing
	}

	repository := filepath.Join(filepath.Dir(mkcpRepositoryRoot(t)), "mihomo")
	output := filepath.Join(workDir, "mihomo")
	command := exec.Command("go", "build", "-o", output, ".")
	command.Dir = repository
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build Mihomo: %v\n%s", err, combined)
	}
	return output
}

func mkcpRepositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("failed to locate repository root")
		}
		directory = parent
	}
}

func startMKCPE2EProcess(t *testing.T, binary string, arguments ...string) *mkcpE2EProcess {
	t.Helper()
	process := &mkcpE2EProcess{
		command: exec.Command(binary, arguments...),
		done:    make(chan struct{}),
	}
	process.command.Stdout = &process.logs
	process.command.Stderr = &process.logs
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := process.command.Wait()
		process.mu.Lock()
		process.exitErr = err
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() { stopMKCPE2EProcess(t, process) })
	return process
}

func stopMKCPE2EProcess(t *testing.T, process *mkcpE2EProcess) {
	t.Helper()
	select {
	case <-process.done:
		return
	default:
	}
	if process.command.Process != nil {
		_ = process.command.Process.Kill()
	}
	select {
	case <-process.done:
	case <-time.After(3 * time.Second):
		t.Errorf("process %s did not exit", process.command.Path)
	}
}

func (p *mkcpE2EProcess) err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitErr
}

func waitMKCPForwarding(t *testing.T, server, client *mkcpE2EProcess, socksPort int, destination *net.TCPAddr) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = runMKCPSOCKSTCP(socksPort, destination, []byte("mkcp-ready"), 750*time.Millisecond)
		if lastErr == nil {
			return
		}
		for name, process := range map[string]*mkcpE2EProcess{"server": server, "client": client} {
			select {
			case <-process.done:
				t.Fatalf("mKCP %s exited before forwarding became ready: %v\n%s", name, process.err(), process.logs.String())
			default:
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("mKCP forwarding did not become ready: %v", lastErr)
}

func runMKCPSOCKSTCP(socksPort int, destination *net.TCPAddr, payload []byte, timeout time.Duration) error {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), timeout)
	if err != nil {
		return fmt.Errorf("dial SOCKS: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if err := mkcpSOCKSGreeting(connection); err != nil {
		return fmt.Errorf("SOCKS greeting: %w", err)
	}
	request := append([]byte{5, 1, 0, 1}, destination.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(destination.Port))
	if _, err := connection.Write(request); err != nil {
		return fmt.Errorf("SOCKS connect request: %w", err)
	}
	if _, err := readMKCPSOCKSReplyAddress(connection); err != nil {
		return fmt.Errorf("SOCKS connect reply: %w", err)
	}
	if _, err := io.Copy(connection, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("write TCP payload: %w", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		return fmt.Errorf("read TCP payload: %w", err)
	}
	if !bytes.Equal(response, payload) {
		return fmt.Errorf("TCP response does not match the %d-byte payload", len(payload))
	}
	return nil
}

func runMKCPSOCKSUDP(socksPort int, destination *net.UDPAddr, payload []byte) error {
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial SOCKS control connection: %w", err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	if err := mkcpSOCKSGreeting(control); err != nil {
		return fmt.Errorf("SOCKS greeting: %w", err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fmt.Errorf("SOCKS UDP associate request: %w", err)
	}
	relay, err := readMKCPSOCKSReplyAddress(control)
	if err != nil {
		return fmt.Errorf("SOCKS UDP associate reply: %w", err)
	}
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}

	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	packet := append([]byte{0, 0, 0, 1}, destination.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(destination.Port))
	packet = append(packet, payload...)
	if _, err := connection.WriteToUDP(packet, relay); err != nil {
		return fmt.Errorf("write SOCKS UDP payload: %w", err)
	}
	response := make([]byte, 65535)
	n, _, err := connection.ReadFromUDP(response)
	if err != nil {
		return fmt.Errorf("read SOCKS UDP payload: %w", err)
	}
	offset, err := mkcpSOCKSAddressEnd(response[:n], 3)
	if err != nil {
		return err
	}
	if !bytes.Equal(response[offset:n], payload) {
		return fmt.Errorf("UDP response does not match the %d-byte payload", len(payload))
	}
	return nil
}

func mkcpSOCKSGreeting(connection net.Conn) error {
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if response[0] != 5 || response[1] != 0 {
		return fmt.Errorf("unexpected SOCKS greeting response %x", response)
	}
	return nil
}

func readMKCPSOCKSReplyAddress(connection net.Conn) (*net.UDPAddr, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 {
		return nil, fmt.Errorf("unexpected SOCKS reply %x", header)
	}

	var ip net.IP
	switch header[3] {
	case 1:
		ip = make([]byte, net.IPv4len)
	case 4:
		ip = make([]byte, net.IPv6len)
	case 3:
		var encodedLength [1]byte
		if _, err := io.ReadFull(connection, encodedLength[:]); err != nil {
			return nil, err
		}
		domain := make([]byte, int(encodedLength[0]))
		if _, err := io.ReadFull(connection, domain); err != nil {
			return nil, err
		}
		resolved, err := net.ResolveIPAddr("ip", string(domain))
		if err != nil {
			return nil, err
		}
		ip = resolved.IP
	default:
		return nil, fmt.Errorf("unexpected SOCKS address family %d", header[3])
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

func mkcpSOCKSAddressEnd(packet []byte, offset int) (int, error) {
	if len(packet) <= offset {
		return 0, io.ErrUnexpectedEOF
	}
	switch packet[offset] {
	case 1:
		offset += 1 + net.IPv4len + 2
	case 4:
		offset += 1 + net.IPv6len + 2
	case 3:
		if len(packet) <= offset+1 {
			return 0, io.ErrUnexpectedEOF
		}
		offset += 1 + 1 + int(packet[offset+1]) + 2
	default:
		return 0, fmt.Errorf("unexpected SOCKS datagram address family %d", packet[offset])
	}
	if len(packet) < offset {
		return 0, io.ErrUnexpectedEOF
	}
	return offset, nil
}

func freeMKCPTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func freeMKCPUDPPort(t *testing.T) int {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := connection.LocalAddr().(*net.UDPAddr).Port
	_ = connection.Close()
	return port
}

func startMKCPTCPEcho(t *testing.T) *net.TCPAddr {
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
	return listener.Addr().(*net.TCPAddr)
}

func startMKCPUDPEcho(t *testing.T) *net.UDPAddr {
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
	return connection.LocalAddr().(*net.UDPAddr)
}
