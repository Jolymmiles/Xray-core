//go:build integration && stress && performance

package singmux_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	// hysteriaUDPPerformanceRevision is the server before IPv6 UDP addresses
	// were parsed from the message bytes: the Hysteria 2.14.0 quic-go bump
	// alone.
	hysteriaUDPPerformanceRevision = "7795bd6c1a1679f8d8b88363856753282786b62a"
	hysteriaUDPPerformanceLabel    = "hysteria-udp-baseline"

	// hysteriaUDPLoadPackets is the packets of one sample;
	// XRAY_HYSTERIA_UDP_PACKETS overrides it.
	hysteriaUDPLoadPackets = 200000
	hysteriaUDPLoadPayload = 64
	// hysteriaUDPLoadWindow bounds the datagrams in flight, so the load is a
	// closed loop that measures throughput instead of queue drops.
	hysteriaUDPLoadWindow = 32
	// hysteriaUDPLoadDeadline bounds one sample: at about 80,000 packets per
	// second the default sample takes under three seconds.
	hysteriaUDPLoadDeadline = 2 * time.Minute
)

// TestHysteriaUDPPerformanceAgainstBaseline sends small UDP packets through an
// Xray Hysteria client to a baseline and a candidate Xray Hysteria server, in
// alternating rounds, and compares delivered packets per second and server CPU
// time per packet. Set XRAY_HYSTERIA_UDP_BASELINE to compare another revision.
func TestHysteriaUDPPerformanceAgainstBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("Hysteria UDP performance comparison")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// Both servers carry the release tags whatever GOFLAGS says: a go test
	// -tags flag does not reach the go build commands the test runs.
	releaseBuild := []string{"-trimpath", "-buildvcs=false", "-tags", "http2legacy"}
	candidateBinary := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray-candidate"), xrayRoot, "./main", releaseBuild...)
	revision := hysteriaUDPPerformanceRevision
	if override := os.Getenv("XRAY_HYSTERIA_UDP_BASELINE"); override != "" {
		revision = override
	}
	baselineBinary := buildXrayRevision(t, workDir, hysteriaUDPPerformanceLabel, revision, "-tags", "http2legacy")
	binaries := e2eBinaries{xray: candidateBinary}
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	ipv4Echo := startUDPEcho(t).(*net.UDPAddr)
	ipv6Echoes := startUDPEchoIPv6(t, 16)

	packets := hysteriaUDPLoadPackets
	if override := os.Getenv("XRAY_HYSTERIA_UDP_PACKETS"); override != "" {
		if packets, err = strconv.Atoi(override); err != nil || packets <= 0 {
			t.Fatalf("XRAY_HYSTERIA_UDP_PACKETS=%q is not a positive packet count", override)
		}
	}

	baseline := startHysteriaPerformanceTopology(t, workDir, binaries, baselineBinary, certificate, privateKey, tcpEcho, "baseline")
	candidate := startHysteriaPerformanceTopology(t, workDir, binaries, candidateBinary, certificate, privateKey, tcpEcho, "candidate")

	// The builds above leave the host busy for a while; a full-size load on
	// both paths settles it before any mode is measured.
	runHysteriaUDPLoad(t, baseline, []*net.UDPAddr{ipv4Echo}, packets)
	runHysteriaUDPLoad(t, candidate, []*net.UDPAddr{ipv4Echo}, packets)

	modes := []struct {
		name    string
		targets []*net.UDPAddr
	}{
		{name: "ipv4", targets: []*net.UDPAddr{ipv4Echo}},
		{name: "ipv6-one", targets: ipv6Echoes[:1]},
		{name: "ipv6-four", targets: ipv6Echoes[:4]},
		{name: "ipv6-sixteen", targets: ipv6Echoes},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			// Warm both paths up outside the timed rounds.
			warmup := max(packets/4, 1)
			runHysteriaUDPLoad(t, baseline, mode.targets, warmup)
			runHysteriaUDPLoad(t, candidate, mode.targets, warmup)

			var baselineSamples, candidateSamples []hysteriaUDPLoadResult
			for round := range performanceRounds {
				measureBaseline := func() {
					baselineSamples = append(baselineSamples, runHysteriaUDPLoad(t, baseline, mode.targets, packets))
				}
				measureCandidate := func() {
					candidateSamples = append(candidateSamples, runHysteriaUDPLoad(t, candidate, mode.targets, packets))
				}
				if round%2 == 0 {
					measureBaseline()
					measureCandidate()
				} else {
					measureCandidate()
					measureBaseline()
				}
			}
			reportHysteriaUDPLoad(t, mode.name, baselineSamples, candidateSamples)
		})
	}
}

type hysteriaUDPLoadResult struct {
	sent, received int
	elapsed        time.Duration
	serverCPU      time.Duration
}

func (r hysteriaUDPLoadResult) packetsPerSecond() float64 {
	return float64(r.received) / r.elapsed.Seconds()
}

func (r hysteriaUDPLoadResult) serverCPUPerPacket() time.Duration {
	if r.received == 0 {
		return 0
	}
	return r.serverCPU / time.Duration(r.received)
}

func startHysteriaPerformanceTopology(t *testing.T, workDir string, binaries e2eBinaries, serverBinary, certificate, privateKey string, tcpEcho *net.TCPAddr, name string) *stressTopology {
	t.Helper()
	serverPort := freeUDPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, "hysteria-udp-performance-"+name)
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(scenarioDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(scenarioDir, "server.key"))
	quiet := func(config []byte) []byte {
		return bytes.ReplaceAll(config, []byte(`"loglevel": "warning"`), []byte(`"loglevel": "warning", "access": "none"`))
	}
	serverPath := filepath.Join(scenarioDir, "server.json")
	writeConfig(t, serverPath, quiet(xrayHysteriaServerConfig(t, serverPort, certificate, privateKey, false)))
	serverArgs := []string{"run", "-config", serverPath}
	server := startE2EProcess(t, serverBinary, serverArgs...)

	clientBinary, clientArgs, clientConfig := hysteriaClientConfig(t, binaries, "xray", serverPort, socksPort, certificate, false)
	clientPath := filepath.Join(scenarioDir, "client.json")
	clientArgs = replaceConfigPath(clientArgs, clientPath)
	writeConfig(t, clientPath, quiet(clientConfig))
	client := startReadyE2EClient(t, "xray", clientBinary, clientArgs, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s server logs:\n%s", name, server.logs.String())
			t.Logf("%s client logs:\n%s", name, client.logs.String())
		}
	})
	waitSOCKSTCPForwarding(t, client, socksPort, tcpEcho)
	return &stressTopology{serverBinary: serverBinary, serverArgs: serverArgs, serverPort: serverPort, client: client, server: server, socksPort: socksPort}
}

// runHysteriaUDPLoad sends packets through one SOCKS UDP association, cycling
// through targets, with at most hysteriaUDPLoadWindow packets awaiting a reply.
// Each reply frees one slot. A lost reply never frees its slot, so losses
// shrink the window; when no slot frees within 200 ms the next packet goes out
// anyway, and its reply restores one slot. A run with losses therefore
// measures a smaller window and includes the stalls in its elapsed time, which
// is why reportHysteriaUDPLoad fails a mode that loses more than 1%.
func runHysteriaUDPLoad(t *testing.T, topology *stressTopology, targets []*net.UDPAddr, packets int) hysteriaUDPLoadResult {
	t.Helper()
	association := openSOCKSUDPAssociation(t, topology.socksPort)
	defer association.udp.Close()
	defer association.control.Close()

	datagrams := make([][]byte, len(targets))
	for index, target := range targets {
		datagrams[index] = append(appendSOCKSUDPAddress([]byte{0, 0, 0}, target), make([]byte, hysteriaUDPLoadPayload)...)
	}
	tokens := make(chan struct{}, hysteriaUDPLoadWindow)
	for range hysteriaUDPLoadWindow {
		tokens <- struct{}{}
	}
	var received atomic.Int64
	var lastReceive atomic.Int64
	receiverDone := make(chan struct{})
	// Closing the socket ends the receiver on every exit path, t.Fatal
	// included; it is joined before the function returns.
	defer func() {
		_ = association.udp.Close()
		<-receiverDone
	}()
	go func() {
		defer close(receiverDone)
		buffer := make([]byte, 2048)
		for received.Load() < int64(packets) {
			_ = association.udp.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := association.udp.ReadFromUDP(buffer); err != nil {
				return
			}
			received.Add(1)
			lastReceive.Store(time.Now().UnixNano())
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}()

	cpuBefore := processCPUTime(t, topology.server.command.Process.Pid)
	started := time.Now()
	deadline := started.Add(hysteriaUDPLoadDeadline)
	stall := time.NewTimer(time.Hour)
	defer stall.Stop()
	for index := range packets {
		select {
		case <-tokens:
		case <-receiverDone:
			// The receiver stops early only when replies stopped for a
			// second; waiting out the remaining packets would take hours.
			t.Fatalf("UDP replies stopped after %d of %d sent packets (%d received)", index, packets, received.Load())
		default:
			if time.Now().After(deadline) {
				t.Fatalf("UDP sample exceeded %s after %d of %d packets (%d received)", hysteriaUDPLoadDeadline, index, packets, received.Load())
			}
			stall.Reset(200 * time.Millisecond)
			select {
			case <-tokens:
			case <-stall.C:
			case <-receiverDone:
				t.Fatalf("UDP replies stopped after %d of %d sent packets (%d received)", index, packets, received.Load())
			}
		}
		if _, err := association.udp.WriteToUDP(datagrams[index%len(datagrams)], association.relay); err != nil {
			t.Fatalf("send packet %d: %v", index, err)
		}
	}
	select {
	case <-receiverDone:
	case <-time.After(time.Until(deadline) + 2*time.Second):
		t.Fatalf("UDP sample exceeded %s waiting for replies (%d of %d received)", hysteriaUDPLoadDeadline, received.Load(), packets)
	}
	cpuAfter := processCPUTime(t, topology.server.command.Process.Pid)
	result := hysteriaUDPLoadResult{
		sent:      packets,
		received:  int(received.Load()),
		elapsed:   time.Unix(0, lastReceive.Load()).Sub(started),
		serverCPU: cpuAfter - cpuBefore,
	}
	if result.received == 0 || result.elapsed <= 0 {
		t.Fatalf("no UDP replies through the Hysteria path (%d sent)", packets)
	}
	return result
}

// processCPUTime returns the CPU time a process has run, summed over its
// threads from /proc/<pid>/task/*/schedstat (nanoseconds).
func processCPUTime(t *testing.T, pid int) time.Duration {
	t.Helper()
	if runtime.GOOS != "linux" {
		return 0
	}
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatalf("list threads of %d: %v", pid, err)
	}
	var total time.Duration
	for _, task := range tasks {
		content, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/schedstat", pid, task.Name()))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue // the thread exited
		}
		if err != nil {
			t.Fatalf("read schedstat of thread %s of %d: %v", task.Name(), pid, err)
		}
		fields := strings.Fields(string(content))
		if len(fields) == 0 {
			t.Fatalf("empty schedstat of thread %s of %d", task.Name(), pid)
		}
		nanoseconds, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			t.Fatalf("parse schedstat of thread %s: %v", task.Name(), err)
		}
		total += time.Duration(nanoseconds)
	}
	// A kernel without CONFIG_SCHED_INFO reports nothing here; a zero would
	// make the CPU ratio NaN and pass the budget check unmeasured.
	if total <= 0 {
		t.Fatalf("no CPU time for process %d in /proc/%d/task/*/schedstat", pid, pid)
	}
	return total
}

func medianFloat(samples []float64) float64 {
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}

func reportHysteriaUDPLoad(t *testing.T, mode string, baseline, candidate []hysteriaUDPLoadResult) {
	t.Helper()
	summarize := func(samples []hysteriaUDPLoadResult) (pps, cpu []float64, lost int) {
		for _, sample := range samples {
			pps = append(pps, sample.packetsPerSecond())
			cpu = append(cpu, float64(sample.serverCPUPerPacket().Nanoseconds()))
			lost += sample.sent - sample.received
		}
		return pps, cpu, lost
	}
	baselinePPS, baselineCPU, baselineLost := summarize(baseline)
	candidatePPS, candidateCPU, candidateLost := summarize(candidate)
	format := func(values []float64) string {
		parts := make([]string, len(values))
		for index, value := range values {
			parts[index] = strconv.FormatFloat(value, 'f', 0, 64)
		}
		return strings.Join(parts, " ")
	}
	ppsRatio := medianFloat(candidatePPS) / medianFloat(baselinePPS)
	cpuRatio := medianFloat(candidateCPU) / medianFloat(baselineCPU)
	t.Logf("%s pps baseline=[%s] candidate=[%s]", mode, format(baselinePPS), format(candidatePPS))
	t.Logf("%s server CPU ns/packet baseline=[%s] candidate=[%s]", mode, format(baselineCPU), format(candidateCPU))
	t.Logf("%s median pps baseline=%.0f candidate=%.0f ratio=%.3f; server CPU ns/packet baseline=%.0f candidate=%.0f ratio=%.3f; lost baseline=%d candidate=%d of %d each",
		mode, medianFloat(baselinePPS), medianFloat(candidatePPS), ppsRatio, medianFloat(baselineCPU), medianFloat(candidateCPU), cpuRatio,
		baselineLost, candidateLost, baseline[0].sent*len(baseline))
	total := 0
	for _, sample := range baseline {
		total += sample.sent
	}
	if baselineLost*100 > total || candidateLost*100 > total {
		t.Errorf("%s lost more than 1%% of packets (baseline %d, candidate %d of %d): the load measures drops, not throughput", mode, baselineLost, candidateLost, total)
	}
	if runtime.GOOS != "linux" || os.Getenv("XRAY_NATIVE_LINUX_RELEASE") != "1" {
		t.Log("diagnostics only; set XRAY_NATIVE_LINUX_RELEASE=1 on a native Linux host to enforce the 10% regression budget")
		return
	}
	if ppsRatio < 0.90 {
		t.Errorf("%s candidate pps regression %.1f%% exceeds 10%%", mode, (1-ppsRatio)*100)
	}
	if cpuRatio > 1.10 {
		t.Errorf("%s candidate server CPU per packet regression %.1f%% exceeds 10%%", mode, (cpuRatio-1)*100)
	}
}
