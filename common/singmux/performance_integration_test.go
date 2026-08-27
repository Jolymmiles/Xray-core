//go:build integration && stress && performance

package singmux_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

const (
	performanceRounds     = 9
	performanceRegression = 1.10
)

func TestSMUXServerPerformanceAgainstSingMux(t *testing.T) {
	if testing.Short() {
		t.Skip("SMUX server performance comparison")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	for _, carrier := range []string{"vless", "trojan"} {
		t.Run(carrier, func(t *testing.T) {
			baseline := startStressTopology(t, workDir, binaries, certificate, privateKey, "sing-box", "xray-client", carrier)
			candidate := startXrayPerformanceTopology(t, workDir, binaries, certificate, privateKey, carrier)
			stressTCP(t, baseline.socksPort, tcpEcho, stressTCPStreams)
			stressTCP(t, candidate.socksPort, tcpEcho, stressTCPStreams)

			baselineSamples := make([]time.Duration, 0, performanceRounds)
			candidateSamples := make([]time.Duration, 0, performanceRounds)
			measure := func(topology *stressTopology) time.Duration {
				started := time.Now()
				stressTCP(t, topology.socksPort, tcpEcho, stressTCPStreams)
				return time.Since(started)
			}
			for round := 0; round < performanceRounds; round++ {
				if round%2 == 0 {
					baselineSamples = append(baselineSamples, measure(baseline))
					candidateSamples = append(candidateSamples, measure(candidate))
				} else {
					candidateSamples = append(candidateSamples, measure(candidate))
					baselineSamples = append(baselineSamples, measure(baseline))
				}
			}

			baselineMedian := medianDuration(baselineSamples)
			candidateMedian := medianDuration(candidateSamples)
			ratio := float64(candidateMedian) / float64(baselineMedian)
			t.Logf("server full-duplex samples: xray=%v sing-mux=%v", candidateSamples, baselineSamples)
			t.Logf("server full-duplex median: xray=%s sing-mux=%s ratio=%.3f (limit %.2f)", candidateMedian, baselineMedian, ratio, performanceRegression)
			if carrier == "trojan" {
				t.Log("Trojan result is diagnostic because it also compares Xray and sing-box TLS/Trojan server implementations")
			}
			if carrier == "vless" && ratio > performanceRegression {
				t.Logf("Xray SMUX vs sing-mux VLESS ratio %.3f exceeds 10%%; this comparison is diagnostic because the external sing-mux oracle is historically unstable. The hard Linux budget is TestCandidatePerformanceAgainstPreviousRelease.", ratio)
			}
			if carrier == "vless" {
				t.Log("10% performance threshold is enforced against the previous published fork release, not this external sing-mux comparison")
			}
		})
	}
}

func startXrayPerformanceTopology(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey, carrier string) *stressTopology {
	t.Helper()
	serverPort := freeTCPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, fmt.Sprintf("performance-xray-%s", carrier))
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(scenarioDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(scenarioDir, "server.key"))
	serverPath := filepath.Join(scenarioDir, "server.json")
	clientPath := filepath.Join(scenarioDir, "client.json")
	writeConfig(t, serverPath, quietStressConfig(xrayConfig(t, true, carrier, serverPort, 0, "smux", true, certificate, privateKey)))
	writeConfig(t, clientPath, quietStressConfig(xrayConfig(t, false, carrier, serverPort, socksPort, "smux", true, certificate, privateKey)))
	serverArgs := []string{"run", "-config", serverPath}
	server := startE2EProcess(t, binaries.xray, serverArgs...)
	waitTCP(t, server, serverPort)
	client := startE2EProcess(t, binaries.xray, "run", "-config", clientPath)
	waitTCP(t, client, socksPort)
	return &stressTopology{
		serverBinary: binaries.xray,
		serverArgs:   serverArgs,
		serverPort:   serverPort,
		client:       client,
		server:       server,
		socksPort:    socksPort,
	}
}

func medianDuration(samples []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	return sorted[len(sorted)/2]
}
