//go:build integration && stress

package singmux_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	remnaNodeMemoryTargetBytes = uint64(5 << 30)
	remnaNodeProfileBatchSize  = 64
	// Keep this diagnostic expectation aligned with the production Service cap.
	remnaNodeSMUXHandlerLimit = 512
)

func TestRemnaNodeMemoryProfileConfigOnlyAddsMetrics(t *testing.T) {
	dnsSet := &deploymentDNSSet{servers: []*deploymentDNSUpstream{
		{address: "h2c+local://127.0.0.1:18001/dns-query"},
		{address: "h2c+local://127.0.0.1:18002/dns-query"},
		{address: "tcp+local://127.0.0.1:18003"},
		{address: "tcp+local://127.0.0.1:18004"},
	}}
	base := remnaNodeServerConfig(t, 1443, 18443, "/tmp/access.log", "/tmp/error.log", "/tmp/nginx.sock", dnsSet)
	profile := remnaNodeMemoryProfileConfig(t, base, 19090)

	var got map[string]any
	if err := json.Unmarshal(profile, &got); err != nil {
		t.Fatal(err)
	}
	metrics, ok := got["metrics"].(map[string]any)
	if !ok || metrics["listen"] != "127.0.0.1:19090" {
		t.Fatalf("metrics config = %#v", got["metrics"])
	}
	delete(got, "metrics")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalJSON(t, encoded) != canonicalJSON(t, base) {
		t.Fatalf("memory profile changed the deployment config: got %s, want %s", encoded, base)
	}
}

func TestRemnaNodeDirectMemoryClientDisablesMultiplexing(t *testing.T) {
	base := remnaNodeXrayClientConfig(t, 1443, 1080, deploymentRouteUUID, true)
	direct := remnaNodeDirectMemoryClientConfig(t, base)

	var config map[string]any
	if err := json.Unmarshal(direct, &config); err != nil {
		t.Fatal(err)
	}
	outbounds := config["outbounds"].([]any)
	outbound := outbounds[0].(map[string]any)
	for _, field := range []string{"smux", "mux"} {
		if _, exists := outbound[field]; exists {
			t.Fatalf("direct memory client retained %q: %#v", field, outbound[field])
		}
	}
	logConfig := config["log"].(map[string]any)
	if logConfig["access"] != "none" {
		t.Fatalf("direct generator access log = %#v, want none", logConfig["access"])
	}
}

func TestRemnaNodeServerMemoryProfile(t *testing.T) {
	if os.Getenv("XRAY_REMNANODE_MEMORY_PROFILE") != "1" {
		t.Skip("set XRAY_REMNANODE_MEMORY_PROFILE=1 to run the destructive five-GiB process profile")
	}
	runRemnaNodeServerMemoryProfile(t, true)
}

func TestRemnaNodeDirectServerMemoryProfile(t *testing.T) {
	if os.Getenv("XRAY_REMNANODE_DIRECT_MEMORY_PROFILE") != "1" {
		t.Skip("set XRAY_REMNANODE_DIRECT_MEMORY_PROFILE=1 to run the destructive direct-connection five-GiB process profile")
	}
	runRemnaNodeServerMemoryProfile(t, false)
}

func runRemnaNodeServerMemoryProfile(t *testing.T, useSMUX bool) {
	t.Helper()
	if testing.Short() {
		t.Skip("RemnaNode process memory profile")
	}

	targetBytes := configuredRemnaNodeMemoryTarget(t)
	workDir := t.TempDir()
	profileDir := os.Getenv("XRAY_REMNANODE_PROFILE_DIR")
	if profileDir == "" {
		profileDir = filepath.Join(workDir, "profiles")
	}
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}

	binaries := buildE2EBinaries(t, workDir)
	certificate, certificateKey := generateCertificate(t, workDir)
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LOCATION_ASSET", filepath.Join(xrayRoot, "resources"))

	dnsSet := startDeploymentDNS(t, "::1")
	realityTarget, _ := startDeploymentRealityTarget(t, certificate, certificateKey)
	healthBaseline := captureLoopbackHealth(t)
	defer assertLoopbackHealth(t, healthBaseline)

	muxPort := freeTCPPort(t)
	directPort := freeTCPPort(t)
	metricsPort := freeTCPPort(t)
	httpPort := startDeploymentHTTPServers(t, "::1")
	sinks := startRemnaNodeProfileSinks(t, 4)
	accessPath := filepath.Join(workDir, "access.log")
	errorPath := filepath.Join(workDir, "error.log")
	serverPath := filepath.Join(workDir, "server.json")
	serverConfig := remnaNodeServerConfig(t, muxPort, directPort, accessPath, errorPath, realityTarget, dnsSet)
	writeConfig(t, serverPath, remnaNodeMemoryProfileConfig(t, serverConfig, metricsPort))
	server := startE2EProcess(t, binaries.xray, "run", "-config", serverPath)
	waitTCP(t, server, muxPort)
	waitTCP(t, server, directPort)
	waitTCP(t, server, metricsPort)

	clientPorts := make([]int, 4)
	clients := make([]*e2eProcess, 0, len(clientPorts))
	for index := range clientPorts {
		clientPorts[index] = freeTCPPort(t)
		clientPath := filepath.Join(workDir, fmt.Sprintf("client-%d.json", index))
		serverPort := muxPort
		clientConfig := remnaNodeXrayClientConfig(t, serverPort, clientPorts[index], deploymentRouteUUID, useSMUX)
		if useSMUX {
			clientConfig = remnaNodeMemoryClientConfig(t, clientConfig)
		} else {
			if index%2 == 1 {
				serverPort = directPort
				clientConfig = remnaNodeXrayClientConfig(t, serverPort, clientPorts[index], deploymentRouteUUID, false)
			}
			clientConfig = remnaNodeDirectMemoryClientConfig(t, clientConfig)
		}
		writeConfig(t, clientPath, clientConfig)
		client := startE2EProcess(t, binaries.xray, "run", "-config", clientPath)
		waitSOCKS(t, client, clientPorts[index])
		clients = append(clients, client)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		t.Logf("memory-profile server logs:\n%s", server.logs.String())
		for index, client := range clients {
			t.Logf("memory-profile client %d logs:\n%s", index, client.logs.String())
		}
		if content, err := os.ReadFile(errorPath); err == nil {
			t.Logf("memory-profile error log:\n%s", content)
		}
		if content, err := os.ReadFile(accessPath); err == nil {
			t.Logf("memory-profile access log:\n%s", content)
		}
	})

	probeClients := 1
	if !useSMUX {
		probeClients = 2
	}
	for index := range probeClients {
		if response := waitDeploymentHTTPForwarding(t, clients[index], clientPorts[index], httpPort, "www.google.com"); !bytes.Contains([]byte(response), []byte("family=ipv4")) {
			t.Fatalf("pre-pressure deployment request through client %d failed: %q", index, response)
		}
	}

	baseline := captureProcessResources(t, server.command.Process.Pid)
	mode := "SMUX streams"
	if !useSMUX {
		mode = "direct connections"
	}
	t.Logf("RemnaNode Xray PID=%d mode=%s baseline rss=%d KiB threads=%d fds=%d", server.command.Process.Pid, mode, baseline.rssKiB, baseline.threads, baseline.fds)
	previousRSS := baseline.rssKiB
	heldConnections := make([]net.Conn, 0, remnaNodeProfileBatchSize)
	stoppedByAdmission := false
	t.Cleanup(func() {
		for _, connection := range heldConnections {
			_ = connection.Close()
		}
	})

	for uint64(previousRSS)*1024 < targetBytes {
		batch, batchErr := openRemnaNodeProfileBatch(clientPorts, sinks.ports, remnaNodeProfileBatchSize)
		heldConnections = append(heldConnections, batch...)
		snapshot := captureProcessResources(t, server.command.Process.Pid)
		t.Logf("RemnaNode Xray PID=%d mode=%s connections=%d rss=%d KiB threads=%d fds=%d target=%d bytes", server.command.Process.Pid, mode, len(heldConnections), snapshot.rssKiB, snapshot.threads, snapshot.fds, targetBytes)
		if batchErr != nil {
			if !useSMUX || len(heldConnections) < remnaNodeSMUXHandlerLimit {
				captureRemnaNodeProfiles(t, metricsPort, profileDir)
				t.Fatalf("full Xray process load stopped before target: rss=%d KiB streams=%d: %v", snapshot.rssKiB, len(heldConnections), batchErr)
			}
			stoppedByAdmission = true
			t.Logf("SMUX admission cap rejected excess load at %d active streams: %v", len(heldConnections), batchErr)
			previousRSS = snapshot.rssKiB
			break
		}
		if snapshot.rssKiB <= previousRSS {
			captureRemnaNodeProfiles(t, metricsPort, profileDir)
			t.Fatalf("full Xray process made no measurable RSS progress: previous=%d KiB current=%d KiB streams=%d", previousRSS, snapshot.rssKiB, len(heldConnections))
		}
		previousRSS = snapshot.rssKiB
	}

	captureRemnaNodeProfiles(t, metricsPort, profileDir)
	if useSMUX && len(heldConnections) >= remnaNodeSMUXHandlerLimit {
		// Prove that capacity is released and the server accepts new work after
		// shedding overload. The forwarding helper observes readiness instead of
		// relying on a scheduler sleep.
		_ = heldConnections[0].Close()
		heldConnections = heldConnections[1:]
	}
	for index := range probeClients {
		if response := waitDeploymentHTTPForwarding(t, clients[index], clientPorts[index], httpPort, "www.google.com"); !bytes.Contains([]byte(response), []byte("family=ipv4")) {
			t.Fatalf("post-pressure deployment request through client %d failed: %q", index, response)
		}
	}
	if stoppedByAdmission {
		t.Logf("full RemnaNode Xray process remained responsive at the SMUX admission cap: pid=%d rss=%d KiB active-streams=%d profiles=%s", server.command.Process.Pid, previousRSS, len(heldConnections), profileDir)
		return
	}
	t.Logf("full RemnaNode Xray process reached target: pid=%d mode=%s rss=%d KiB connections=%d profiles=%s", server.command.Process.Pid, mode, previousRSS, len(heldConnections), profileDir)
}

func remnaNodeMemoryProfileConfig(t *testing.T, base []byte, metricsPort int) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(base, &config); err != nil {
		t.Fatal(err)
	}
	config["metrics"] = map[string]any{"listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(metricsPort))}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func remnaNodeMemoryClientConfig(t *testing.T, base []byte) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(base, &config); err != nil {
		t.Fatal(err)
	}
	outbounds := config["outbounds"].([]any)
	outbound := outbounds[0].(map[string]any)
	outbound["smux"] = map[string]any{
		"enabled": true, "protocol": "smux", "maxStreams": 8, "padding": true,
	}
	config["log"] = map[string]any{"loglevel": "warning", "access": "none"}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func remnaNodeDirectMemoryClientConfig(t *testing.T, base []byte) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(base, &config); err != nil {
		t.Fatal(err)
	}
	outbounds := config["outbounds"].([]any)
	outbound := outbounds[0].(map[string]any)
	delete(outbound, "smux")
	delete(outbound, "mux")
	config["log"] = map[string]any{"loglevel": "warning", "access": "none"}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func configuredRemnaNodeMemoryTarget(t *testing.T) uint64 {
	t.Helper()
	value := os.Getenv("XRAY_REMNANODE_MEMORY_TARGET_BYTES")
	if value == "" {
		return remnaNodeMemoryTargetBytes
	}
	target, err := strconv.ParseUint(value, 10, 64)
	if err != nil || target == 0 {
		t.Fatalf("XRAY_REMNANODE_MEMORY_TARGET_BYTES=%q is not a positive byte count", value)
	}
	return target
}

type remnaNodeProfileSinks struct {
	ports       []int
	listeners   []net.Listener
	connections []net.Conn
	mu          sync.Mutex
}

func startRemnaNodeProfileSinks(t *testing.T, count int) *remnaNodeProfileSinks {
	t.Helper()
	sinks := &remnaNodeProfileSinks{ports: make([]int, 0, count), listeners: make([]net.Listener, 0, count)}
	for range count {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sinks.listeners = append(sinks.listeners, listener)
		sinks.ports = append(sinks.ports, listener.Addr().(*net.TCPAddr).Port)
		go func() {
			for {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				sinks.mu.Lock()
				sinks.connections = append(sinks.connections, connection)
				sinks.mu.Unlock()
			}
		}()
	}
	t.Cleanup(func() {
		for _, listener := range sinks.listeners {
			_ = listener.Close()
		}
		sinks.mu.Lock()
		defer sinks.mu.Unlock()
		for _, connection := range sinks.connections {
			_ = connection.Close()
		}
	})
	return sinks
}

type remnaNodeProfileConnection struct {
	connection net.Conn
	err        error
}

func openRemnaNodeProfileBatch(clientPorts, destinationPorts []int, count int) ([]net.Conn, error) {
	results := make(chan remnaNodeProfileConnection, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			connection, err := openRemnaNodeProfileConnection(clientPorts[index%len(clientPorts)], destinationPorts[index%len(destinationPorts)])
			results <- remnaNodeProfileConnection{connection: connection, err: err}
		}(index)
	}
	wait.Wait()
	close(results)

	connections := make([]net.Conn, 0, count)
	var joined error
	for result := range results {
		if result.err != nil {
			joined = errors.Join(joined, result.err)
			if result.connection != nil {
				_ = result.connection.Close()
			}
			continue
		}
		connections = append(connections, result.connection)
	}
	return connections, joined
}

func openRemnaNodeProfileConnection(socksPort, destinationPort int) (net.Conn, error) {
	connection, err := dialSOCKSTCPAttempt(socksPort, "www.google.com", destinationPort)
	if err != nil {
		return nil, err
	}
	if tcpConnection, ok := connection.(*net.TCPConn); ok {
		_ = tcpConnection.SetWriteBuffer(32 * 1024)
	}
	if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		_ = connection.Close()
		return nil, err
	}
	header := fmt.Sprintf("POST /profile HTTP/1.1\r\nHost: www.google.com\r\nContent-Length: %d\r\n\r\n", 1<<30)
	if _, err := io.WriteString(connection, header); err != nil {
		_ = connection.Close()
		return nil, err
	}
	payload := make([]byte, 32*1024)
	for {
		_, err = connection.Write(payload)
		if err == nil {
			continue
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			_ = connection.SetWriteDeadline(time.Time{})
			return connection, nil
		}
		_ = connection.Close()
		return nil, err
	}
}

func captureRemnaNodeProfiles(t *testing.T, metricsPort int, profileDir string) {
	t.Helper()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", metricsPort)
	for name, path := range map[string]string{
		"heap.pb.gz":      "/debug/pprof/heap",
		"allocs.pb.gz":    "/debug/pprof/allocs",
		"goroutine.pb.gz": "/debug/pprof/goroutine",
		"vars.json":       "/debug/vars",
	} {
		response, err := http.Get(baseURL + path) // #nosec G107 -- loopback-only test metrics endpoint
		if err != nil {
			t.Errorf("capture %s: %v", name, err)
			continue
		}
		content, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Errorf("capture %s: HTTP %s", name, response.Status)
			continue
		}
		if readErr != nil {
			t.Errorf("capture %s: %v", name, readErr)
			continue
		}
		if closeErr != nil {
			t.Errorf("capture %s close: %v", name, closeErr)
		}
		if err := os.WriteFile(filepath.Join(profileDir, name), content, 0o600); err != nil {
			t.Errorf("write %s: %v", name, err)
		}
	}
}
