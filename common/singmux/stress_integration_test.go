//go:build integration && stress

package singmux_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	stressTCPStreams   = 128
	stressTCPBytes     = 1 << 20
	stressUDPDatagrams = 10_000
	stressCycles       = 3
)

type stressTopology struct {
	serverBinary string
	serverArgs   []string
	serverPort   int
	client       *e2eProcess
	server       *e2eProcess
	socksPort    int
}

func TestConfiguredStressCycles(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("XRAY_SMUX_STRESS_CYCLES", "")
		if cycles := configuredStressCycles(t); cycles != stressCycles {
			t.Fatalf("configuredStressCycles() = %d, want %d", cycles, stressCycles)
		}
	})
	t.Run("override", func(t *testing.T) {
		t.Setenv("XRAY_SMUX_STRESS_CYCLES", "50")
		if cycles := configuredStressCycles(t); cycles != 50 {
			t.Fatalf("configuredStressCycles() = %d, want 50", cycles)
		}
	})
}

func TestQuietStressConfigDisablesXrayAccessLog(t *testing.T) {
	quiet := quietStressConfig([]byte(`{"log":{"loglevel": "debug"}}`))
	if !bytes.Contains(quiet, []byte(`"access": "none"`)) {
		t.Fatalf("quiet Xray config still enables access logging: %s", quiet)
	}
}

func TestMihomoStressSpreadsOnlyStressClientConnections(t *testing.T) {
	if got := stressTCPStreamsForPeer("mihomo", 128); got != 32 {
		t.Fatalf("Mihomo peak streams = %d, want 32", got)
	}
	if got := stressTCPStreamsForPeer("mihomo", 16); got != 16 {
		t.Fatalf("Mihomo cumulative streams = %d, want 16", got)
	}
	if got := stressTCPStreamsForPeer("sing-box", 128); got != 128 {
		t.Fatalf("sing-box peak streams = %d, want 128", got)
	}
	xrayConfig := xrayConfig(t, false, "vless", 443, 1080, "smux", true, "", "")
	if !bytes.Contains(xrayConfig, []byte(`"maxConnections": 1`)) {
		t.Fatalf("ordinary Xray matrix config lost its single-carrier limit: %s", xrayConfig)
	}

	mihomoConfig := mihomoClientConfig("vless", 443, 1080, "smux", true)
	if !bytes.Contains(mihomoConfig, []byte("max-connections: 1")) {
		t.Fatalf("ordinary Mihomo matrix config lost its single-carrier limit: %s", mihomoConfig)
	}
	if spread := spreadMihomoStressConnections(t, mihomoConfig); !bytes.Contains(spread, []byte("max-connections: 4")) {
		t.Fatalf("Mihomo-client stress config = %s", spread)
	}

	singBoxConfig := singBoxClientConfig(t, "vless", 443, 1080, "smux", true)
	if !bytes.Contains(singBoxConfig, []byte(`"max_connections": 1`)) {
		t.Fatalf("sing-box stress config lost its single-carrier limit: %s", singBoxConfig)
	}
}

func assertNoLinearResourceGrowth(t *testing.T, samples []processResourceSnapshot, cycles int) {
	t.Helper()
	if len(samples) != cycles {
		t.Fatalf("resource samples = %d, want %d", len(samples), cycles)
	}
	for index, sample := range samples {
		t.Logf("client resources after cycle %d: rss=%d KiB threads=%d fds=%d", index+1, sample.rssKiB, sample.threads, sample.fds)
	}
	if len(samples) < 3 {
		return
	}
	middle := len(samples) / 2
	rssFirstGrowth := int64(samples[middle].rssKiB) - int64(samples[0].rssKiB)
	rssSecondGrowth := int64(samples[len(samples)-1].rssKiB) - int64(samples[middle].rssKiB)
	if rssFirstGrowth > 0 && rssSecondGrowth >= rssFirstGrowth/2 && samples[len(samples)-1].rssKiB > samples[0].rssKiB+64*1024 {
		t.Errorf("client RSS shows linear growth across cycles: %+v", samples)
	}
	if samples[0].threads > 0 && samples[0].threads < samples[middle].threads && samples[middle].threads < samples[len(samples)-1].threads && samples[len(samples)-1].threads > samples[0].threads+16 {
		t.Errorf("client thread count shows linear growth across cycles: %+v", samples)
	}
}

func TestSMUXProcessStressAndReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("SMUX process stress suite")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	udpEchoes := make([]*net.UDPAddr, 4)
	for index := range udpEchoes {
		udpEchoes[index] = startUDPEcho(t).(*net.UDPAddr)
	}
	interfaceBaseline := captureLoopbackHealth(t)
	defer assertLoopbackHealth(t, interfaceBaseline)
	tcpStreams := configuredStressTCPStreams(t)
	cycles := configuredStressCycles(t)

	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		for _, carrier := range []string{"vless", "trojan"} {
			name := fmt.Sprintf("%s/xray-server/%s", peer, carrier)
			t.Run(name, func(t *testing.T) {
				topology := startStressTopology(t, workDir, binaries, certificate, privateKey, peer, carrier)
				assertStressPathReady(t, topology.client, topology.socksPort, tcpEcho)
				peerTCPStreams := stressTCPStreamsForPeer(peer, tcpStreams)
				resources := make([]processResourceSnapshot, 0, cycles)
				for cycle := 0; cycle < cycles; cycle++ {
					t.Run(fmt.Sprintf("cycle-%d", cycle+1), func(t *testing.T) {
						stressTCP(t, topology.socksPort, tcpEcho, peerTCPStreams)
						stressUDP(t, topology.socksPort, udpEchoes)
					})
					resources = append(resources, captureProcessResources(t, topology.client.command.Process.Pid))
					if cycle+1 < cycles {
						stopE2EProcess(t, topology.server)
						topology.server = startReadyE2EServer(t, topology.serverBinary, topology.serverArgs, topology.serverPort, "")
						assertStressPathReady(t, topology.client, topology.socksPort, tcpEcho)
					}
				}
				assertNoLinearResourceGrowth(t, resources, cycles)
			})
		}
	}
}

func stressTCPStreamsForPeer(peer string, configured int) int {
	if peer == "mihomo" && configured > 32 {
		return 32
	}
	return configured
}

func configuredStressCycles(t *testing.T) int {
	t.Helper()
	value := os.Getenv("XRAY_SMUX_STRESS_CYCLES")
	if value == "" {
		return stressCycles
	}
	cycles, err := strconv.Atoi(value)
	if err != nil || cycles <= 0 {
		t.Fatalf("XRAY_SMUX_STRESS_CYCLES=%q is not a positive integer", value)
	}
	t.Logf("stress cycle override: %d", cycles)
	return cycles
}

func configuredStressTCPStreams(t *testing.T) int {
	t.Helper()
	value := os.Getenv("XRAY_SMUX_STRESS_TCP_STREAMS")
	if value == "" {
		return stressTCPStreams
	}
	streamCount, err := strconv.Atoi(value)
	if err != nil || streamCount <= 0 {
		t.Fatalf("XRAY_SMUX_STRESS_TCP_STREAMS=%q is not a positive integer", value)
	}
	t.Logf("diagnostic TCP stream override: %d", streamCount)
	return streamCount
}

func startStressTopology(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey, peer, carrier string) *stressTopology {
	t.Helper()
	serverPort := freeTCPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, "stress-"+strings.NewReplacer("/", "-").Replace(t.Name()))
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(scenarioDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(scenarioDir, "server.key"))

	serverArgs := []string{"run", "-config", "server.json"}
	serverConfig := xrayConfig(t, true, carrier, serverPort, 0, "smux", true, certificate, privateKey)
	clientBinary, clientArgs, clientConfig := peerClientConfig(t, binaries, peer, carrier, serverPort, socksPort, "smux", true, certificate)
	serverPath := filepath.Join(scenarioDir, "server.json")
	clientPath := filepath.Join(scenarioDir, "client"+configExtension(peer, false))
	serverConfig = quietStressConfig(serverConfig)
	clientConfig = quietStressConfig(clientConfig)
	if peer == "mihomo" {
		clientConfig = spreadMihomoStressConnections(t, clientConfig)
	}
	serverArgs = replaceConfigPath(serverArgs, serverPath)
	clientArgs = replaceConfigPath(clientArgs, clientPath)
	writeConfig(t, serverPath, serverConfig)
	writeConfig(t, clientPath, clientConfig)

	server := startReadyE2EServer(t, binaries.xray, serverArgs, serverPort, "")
	client := startReadyE2EClient(t, peer, clientBinary, clientArgs, socksPort)

	topology := &stressTopology{
		serverBinary: binaries.xray,
		serverArgs:   serverArgs,
		serverPort:   serverPort,
		client:       client,
		server:       server,
		socksPort:    socksPort,
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stress server logs:\n%s", topology.server.logs.String())
			t.Logf("stress client logs:\n%s", client.logs.String())
		}
	})
	return topology
}

func spreadMihomoStressConnections(t *testing.T, config []byte) []byte {
	t.Helper()
	oldValue := []byte("max-connections: 1")
	newValue := []byte("max-connections: 4")
	if bytes.Count(config, oldValue) != 1 {
		t.Fatalf("Mihomo stress config has %d occurrences of %q, want 1", bytes.Count(config, oldValue), oldValue)
	}
	return bytes.Replace(config, oldValue, newValue, 1)
}

func quietStressConfig(config []byte) []byte {
	config = bytes.ReplaceAll(config, []byte(`"loglevel": "debug"`), []byte(`"loglevel": "warning", "access": "none"`))
	config = bytes.ReplaceAll(config, []byte(`"level": "debug"`), []byte(`"level": "warn"`))
	return config
}

func assertStressPathReady(t *testing.T, client *e2eProcess, socksPort int, destination *net.TCPAddr) {
	t.Helper()
	if err := runSOCKSTCP(socksPort, destination); err != nil {
		t.Fatalf("SOCKS-to-server-to-echo path is not ready after server start: %v\nclient logs:\n%s", err, client.logs.String())
	}
}

func stressTCP(t *testing.T, socksPort int, destination *net.TCPAddr, streamCount int) {
	t.Helper()
	payload := bytes.Repeat([]byte("xray-smux-stress"), stressTCPBytes/len("xray-smux-stress")+1)[:stressTCPBytes]
	errors := make(chan error, streamCount)
	var wait sync.WaitGroup
	for stream := 0; stream < streamCount; stream++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- stressTCPRoundTrip(socksPort, destination, payload)
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func stressTCPRoundTrip(socksPort int, destination *net.TCPAddr, payload []byte) error {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 10*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := socksGreeting(connection); err != nil {
		return err
	}
	request := append([]byte{5, 1, 0, 1}, destination.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(destination.Port))
	if _, err := connection.Write(request); err != nil {
		return err
	}
	if err := readSOCKSReply(connection); err != nil {
		return err
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := io.Copy(connection, bytes.NewReader(payload))
		writeResult <- err
	}()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if err := <-writeResult; err != nil {
		return err
	}
	if !bytes.Equal(response, payload) {
		return fmt.Errorf("TCP stress payload mismatch")
	}
	return nil
}

func stressUDP(t *testing.T, socksPort int, destinations []*net.UDPAddr) {
	t.Helper()
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(2 * time.Minute))
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
	_ = udp.SetDeadline(time.Now().Add(2 * time.Minute))
	response := make([]byte, 65535)
	for sequence := 0; sequence < stressUDPDatagrams; sequence++ {
		destination := destinations[sequence%len(destinations)]
		payload := make([]byte, 8)
		binary.BigEndian.PutUint64(payload, uint64(sequence))
		packet := append([]byte{0, 0, 0, 1}, destination.IP.To4()...)
		packet = binary.BigEndian.AppendUint16(packet, uint16(destination.Port))
		packet = append(packet, payload...)
		if _, err := udp.WriteToUDP(packet, relay); err != nil {
			t.Fatal(err)
		}
		n, _, err := udp.ReadFromUDP(response)
		if err != nil {
			t.Fatal(err)
		}
		offset, err := socksAddressLength(response[:n], 3)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(response[offset:n], payload) {
			t.Fatalf("UDP stress sequence %d payload mismatch", sequence)
		}
	}
}
