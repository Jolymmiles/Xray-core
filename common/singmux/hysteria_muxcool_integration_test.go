//go:build integration

package singmux_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestHysteriaMuxCoolServerSurvivesCarrierTeardown reproduces the production
// crash where Mux.Cool session handlers wrote their End frame through a
// Hysteria link writer that had already been returned to its pool.
func TestHysteriaMuxCoolServerSurvivesCarrierTeardown(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level Hysteria Mux.Cool carrier teardown")
	}
	const (
		cycles        = 10
		heldStreams   = 8
		clientTimeout = 10 * time.Second
	)
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	serverPort := freeUDPPort(t)
	serverPath := filepath.Join(workDir, "server.json")
	writeConfig(t, serverPath, xrayHysteriaServerConfig(t, serverPort, certificate, privateKey, false))
	server := startE2EProcess(t, binaries.xray, "run", "-config", serverPath)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
		}
	})

	for cycle := range cycles {
		socksPort := freeTCPPort(t)
		clientPath := filepath.Join(workDir, "client.json")
		writeConfig(t, clientPath, xrayHysteriaMuxCoolClientConfig(t, binaries, serverPort, socksPort, certificate))
		client := startReadyE2EClient(t, "xray", binaries.xray, []string{"run", "-config", clientPath}, socksPort)
		waitSOCKSTCPForwarding(t, client, socksPort, tcpEcho)

		// Keep several Mux.Cool sessions open on the carrier, then stop the
		// client so the server tears the carrier down under live sessions.
		// Held callbacks are released on every exit path, including t.Fatal.
		release := make(chan struct{})
		releaseHeld := sync.OnceFunc(func() { close(release) })
		t.Cleanup(releaseHeld)
		echoed := make(chan struct{}, heldStreams)
		errs := make(chan error, heldStreams)
		for range heldStreams {
			go func() {
				errs <- runSOCKSTCPWithCallback(socksPort, tcpEcho, func() {
					echoed <- struct{}{}
					<-release
				})
			}()
		}
		for held := 0; held < heldStreams; {
			select {
			case <-echoed:
				held++
			case err := <-errs:
				releaseHeld()
				t.Fatalf("cycle %d: held stream failed before carrier teardown: %v (server exited: %t)", cycle, err, serverExited(server))
			}
		}
		if err := client.command.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
		select {
		case <-client.done:
			client.stopped.Store(true)
		case <-time.After(clientTimeout):
			t.Fatalf("cycle %d: client did not exit after interrupt", cycle)
		}
		releaseHeld()
		for range heldStreams {
			<-errs
		}

		if serverExited(server) {
			t.Fatalf("cycle %d: server exited after carrier teardown", cycle)
		}
	}

	socksPort := freeTCPPort(t)
	clientPath := filepath.Join(workDir, "client.json")
	writeConfig(t, clientPath, xrayHysteriaMuxCoolClientConfig(t, binaries, serverPort, socksPort, certificate))
	client := startReadyE2EClient(t, "xray", binaries.xray, []string{"run", "-config", clientPath}, socksPort)
	waitSOCKSTCPForwarding(t, client, socksPort, tcpEcho)
	testSOCKSTCP(t, socksPort, tcpEcho)
}

func xrayHysteriaMuxCoolClientConfig(t *testing.T, binaries e2eBinaries, serverPort, socksPort int, certificate string) []byte {
	t.Helper()
	_, _, encoded := hysteriaClientConfig(t, binaries, "xray", serverPort, socksPort, certificate, false)
	var config map[string]any
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	outbound := config["outbounds"].([]any)[0].(map[string]any)
	outbound["mux"] = map[string]any{"enabled": true, "concurrency": 8}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func serverExited(server *e2eProcess) bool {
	if server.stopped.Load() {
		return true
	}
	select {
	case <-server.done:
		server.stopped.Store(true)
		return true
	default:
		return false
	}
}
