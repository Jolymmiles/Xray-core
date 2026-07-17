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

func assertNoLinearResourceGrowth(t *testing.T, samples []processResourceSnapshot, cycles int) {
	t.Helper()
	if len(samples) != cycles {
		t.Fatalf("resource samples = %d, want %d", len(samples), cycles)
	}
	for index, sample := range samples {
		t.Logf("client resources after cycle %d: rss=%d KiB threads=%d", index+1, sample.rssKiB, sample.threads)
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

	for _, peer := range []string{"sing-box", "mihomo"} {
		for _, direction := range []string{"xray-client", "xray-server"} {
			for _, carrier := range []string{"vless", "trojan"} {
				name := fmt.Sprintf("%s/%s/%s", peer, direction, carrier)
				t.Run(name, func(t *testing.T) {
					topology := startStressTopology(t, workDir, binaries, certificate, privateKey, peer, direction, carrier)
					resources := make([]processResourceSnapshot, 0, cycles)
					for cycle := 0; cycle < cycles; cycle++ {
						t.Run(fmt.Sprintf("cycle-%d", cycle+1), func(t *testing.T) {
							stressTCP(t, topology.socksPort, tcpEcho, tcpStreams)
							stressUDP(t, topology.socksPort, udpEchoes)
						})
						resources = append(resources, captureProcessResources(t, topology.client.command.Process.Pid))
						if cycle+1 < cycles {
							stopE2EProcess(t, topology.server)
							topology.server = startE2EProcess(t, topology.serverBinary, topology.serverArgs...)
							waitTCP(t, topology.server, topology.serverPort)
						}
					}
					assertNoLinearResourceGrowth(t, resources, cycles)
				})
			}
		}
	}
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

func startStressTopology(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey, peer, direction, carrier string) *stressTopology {
	t.Helper()
	serverPort := freeTCPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, "stress-"+strings.NewReplacer("/", "-").Replace(t.Name()))
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(scenarioDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(scenarioDir, "server.key"))

	var serverBinary string
	var serverArgs []string
	var serverConfig []byte
	var clientBinary string
	var clientArgs []string
	var clientConfig []byte
	if direction == "xray-client" {
		serverBinary, serverArgs, serverConfig = peerServerConfig(t, binaries, peer, carrier, serverPort, true, certificate, privateKey)
		clientBinary = binaries.xray
		clientArgs = []string{"run", "-config", "client.json"}
		clientConfig = xrayConfig(t, false, carrier, serverPort, socksPort, true, certificate, privateKey)
	} else {
		serverBinary = binaries.xray
		serverArgs = []string{"run", "-config", "server.json"}
		serverConfig = xrayConfig(t, true, carrier, serverPort, 0, true, certificate, privateKey)
		clientBinary, clientArgs, clientConfig = peerClientConfig(t, binaries, peer, carrier, serverPort, socksPort, true, certificate)
	}
	serverPath := filepath.Join(scenarioDir, "server"+configExtension(peer, direction == "xray-server"))
	clientPath := filepath.Join(scenarioDir, "client"+configExtension(peer, direction == "xray-client"))
	serverConfig = quietStressConfig(serverConfig)
	clientConfig = quietStressConfig(clientConfig)
	serverArgs = replaceConfigPath(serverArgs, serverPath)
	clientArgs = replaceConfigPath(clientArgs, clientPath)
	writeConfig(t, serverPath, serverConfig)
	writeConfig(t, clientPath, clientConfig)

	server := startE2EProcess(t, serverBinary, serverArgs...)
	waitTCP(t, server, serverPort)
	if peer == "mihomo" && direction == "xray-client" {
		waitProcessLog(t, server, "Initial configuration complete")
	}
	client := startE2EProcess(t, clientBinary, clientArgs...)
	waitSOCKS(t, client, socksPort)
	if peer == "mihomo" && direction == "xray-server" {
		waitProcessLog(t, client, "Initial configuration complete")
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stress server logs:\n%s", server.logs.String())
			t.Logf("stress client logs:\n%s", client.logs.String())
		}
	})
	return &stressTopology{
		serverBinary: serverBinary,
		serverArgs:   serverArgs,
		serverPort:   serverPort,
		client:       client,
		server:       server,
		socksPort:    socksPort,
	}
}

func quietStressConfig(config []byte) []byte {
	config = bytes.ReplaceAll(config, []byte(`"loglevel": "debug"`), []byte(`"loglevel": "warning", "access": "none"`))
	config = bytes.ReplaceAll(config, []byte(`"level": "debug"`), []byte(`"level": "warn"`))
	return config
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
