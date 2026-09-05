//go:build integration && stress && performance

package singmux_test

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const (
	candidatePerformanceRevision = "b7bdfb03fa582cd691197593cc853f6ea209d04f" // v26.8.25-1457
	candidatePerformanceLabel    = "v26.8.25-1457"
)

func TestCandidatePerformanceAgainstPreviousRelease(t *testing.T) {
	if testing.Short() {
		t.Skip("candidate performance comparison")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	candidateBinary := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray-candidate"), xrayRoot, "./main", "-trimpath", "-buildvcs=false")
	binaries := e2eBinaries{xray: candidateBinary}
	oldBinary := buildCandidatePerformanceBaseline(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	for _, carrier := range []string{"vless", "trojan"} {
		t.Run(carrier, func(t *testing.T) {
			baseline := startXrayPerformanceTopologyWithServer(t, workDir, binaries, oldBinary, certificate, privateKey, carrier, "baseline")
			candidate := startXrayPerformanceTopologyWithServer(t, workDir, binaries, binaries.xray, certificate, privateKey, carrier, "candidate")
			stressTCP(t, baseline.socksPort, tcpEcho, stressTCPStreams)
			stressTCP(t, candidate.socksPort, tcpEcho, stressTCPStreams)
			baselineStart := waitProcessResourcesStable(t, baseline.server.command.Process.Pid)
			candidateStart := waitProcessResourcesStable(t, candidate.server.command.Process.Pid)

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

			baselineEnd := captureProcessResources(t, baseline.server.command.Process.Pid)
			candidateEnd := captureProcessResources(t, candidate.server.command.Process.Pid)
			stopE2EProcess(t, baseline.client)
			stopE2EProcess(t, candidate.client)
			baselineQuiescent := waitProcessResourcesDrained(t, baseline.server.command.Process.Pid, baselineStart)
			candidateQuiescent := waitProcessResourcesDrained(t, candidate.server.command.Process.Pid, candidateStart)
			baselineMedian := medianDuration(baselineSamples)
			candidateMedian := medianDuration(candidateSamples)
			ratio := float64(candidateMedian) / float64(baselineMedian)
			t.Logf("%s samples=%v candidate samples=%v", candidatePerformanceLabel, baselineSamples, candidateSamples)
			t.Logf("median %s=%s candidate=%s ratio=%.3f", candidatePerformanceLabel, baselineMedian, candidateMedian, ratio)
			t.Logf("resources %s start=%+v end=%+v quiescent=%+v candidate start=%+v end=%+v quiescent=%+v", candidatePerformanceLabel, baselineStart, baselineEnd, baselineQuiescent, candidateStart, candidateEnd, candidateQuiescent)
			if runtime.GOOS == "linux" && os.Getenv("XRAY_NATIVE_LINUX_RELEASE") != "1" {
				t.Log("Linux Docker/emulation validates the harness only; set XRAY_NATIVE_LINUX_RELEASE=1 on the pinned native host to enforce release budgets")
				return
			}
			if runtime.GOOS != "linux" {
				t.Log("candidate performance and resource budgets are a Linux release gate; this platform records diagnostics only")
				return
			}
			if ratio > 1.10 {
				t.Errorf("candidate median regression %.1f%% exceeds 10%%", (ratio-1)*100)
			}
			if candidateQuiescent.rssKiB > baselineQuiescent.rssKiB+64*1024 {
				t.Errorf("candidate RSS=%d KiB exceeds %s=%d KiB by more than 64 MiB", candidateQuiescent.rssKiB, candidatePerformanceLabel, baselineQuiescent.rssKiB)
			}
			if candidateQuiescent.threads > baselineQuiescent.threads+16 {
				t.Errorf("candidate threads=%d exceed %s=%d by more than 16", candidateQuiescent.threads, candidatePerformanceLabel, baselineQuiescent.threads)
			}
			if candidateQuiescent.fds > baselineQuiescent.fds+8 {
				t.Errorf("candidate fds=%d exceed %s=%d by more than 8", candidateQuiescent.fds, candidatePerformanceLabel, baselineQuiescent.fds)
			}
			// Pooled SMUX carriers keep sockets open during the run, so a
			// start-to-end self-delta is teardown noise. Fail closed only if
			// either server approaches one FD per concurrent stream.
			if baselineEnd.fds > stressTCPStreams || candidateEnd.fds > stressTCPStreams {
				t.Errorf("server FDs under load exceeded %d concurrent streams: %s %d candidate %d", stressTCPStreams, candidatePerformanceLabel, baselineEnd.fds, candidateEnd.fds)
			}
		})
	}
}

func waitProcessResourcesStable(t *testing.T, pid int) processResourceSnapshot {
	t.Helper()
	if runtime.GOOS != "linux" {
		return captureProcessResources(t, pid)
	}
	previous := captureProcessResources(t, pid)
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.Gosched()
		current := captureProcessResources(t, pid)
		fdDelta := current.fds - previous.fds
		if fdDelta < 0 {
			fdDelta = -fdDelta
		}
		if fdDelta <= 2 {
			return current
		}
		if time.Now().After(deadline) {
			return current
		}
		previous = current
	}
}

func waitProcessResourcesDrained(t *testing.T, pid int, baseline processResourceSnapshot) processResourceSnapshot {
	t.Helper()
	if runtime.GOOS != "linux" {
		return captureProcessResources(t, pid)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		current := captureProcessResources(t, pid)
		if current.fds <= baseline.fds+8 && current.threads <= baseline.threads+16 {
			return current
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d resources did not drain to release budgets: baseline=%+v current=%+v", pid, baseline, current)
		}
		runtime.Gosched()
	}
}

func buildCandidatePerformanceBaseline(t *testing.T, workDir string) string {
	t.Helper()
	source := filepath.Join(workDir, candidatePerformanceLabel+"-source")
	binary := filepath.Join(workDir, "xray-"+candidatePerformanceLabel)
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := exec.Command("git", "-C", filepath.Join("..", ".."), "archive", candidatePerformanceRevision)
	extract := exec.Command("tar", "-x", "-C", source)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	extract.Stdin, archive.Stderr, extract.Stderr = pipe, os.Stderr, os.Stderr
	if err := extract.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Run(); err != nil {
		t.Fatal(err)
	}
	if err := extract.Wait(); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "./main")
	build.Dir = source
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", candidatePerformanceLabel, err, output)
	}
	return binary
}

func startXrayPerformanceTopologyWithServer(t *testing.T, workDir string, binaries e2eBinaries, serverBinary, certificate, privateKey, carrier, name string) *stressTopology {
	t.Helper()
	serverPort := freeTCPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, "candidate-performance-"+carrier+"-"+name)
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
	server := startE2EProcess(t, serverBinary, serverArgs...)
	waitTCP(t, server, serverPort)
	client := startE2EProcess(t, binaries.xray, "run", "-config", clientPath)
	waitSOCKS(t, client, socksPort)
	return &stressTopology{serverBinary: serverBinary, serverArgs: serverArgs, serverPort: serverPort, client: client, server: server, socksPort: socksPort}
}
