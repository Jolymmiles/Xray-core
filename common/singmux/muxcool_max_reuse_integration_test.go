//go:build integration

package singmux_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Xray servers that predate mux.maxReuseTimes. They allocate nothing for it:
// the budget is the client's policy and never reaches the wire.
var muxCoolOldServers = []struct{ label, revision string }{
	{"upstream-v26.10.10", "701af60772cda123492f86e383e1fdba066614a9"},
	{"fork-v26.8.25-1457", "163ac98d810cdc1667c1011540e498c6a954ee70"},
}

// TestMuxCoolMaxReuseTimesProcess runs an Xray client with Mux.Cool against an
// Xray VLESS server over TLS and REALITY, through a relay that counts the TCP
// connections the client opens. One session stays open on the first carrier
// while two more open and close one after another. Within the default budget
// of 128 both reuse that carrier; with maxReuseTimes 1 each opens its own.
// The held session echoes again afterwards: an exhausted carrier keeps the
// sessions it already carries.
func TestMuxCoolMaxReuseTimesProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level Mux.Cool reuse budget")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	for _, security := range []string{"tls", "reality"} {
		realityTarget := ""
		if security == "reality" {
			realityTarget = startRealityCoverServer(t, certificate, privateKey)
		}
		serverPort := freeTCPPort(t)
		serverPath := filepath.Join(workDir, "server-"+security+".json")
		writeConfig(t, serverPath, xrayVLESSTCPConfig(t, true, serverPort, 0, security, "", certificate, privateKey, realityTarget))
		server := startE2EProcess(t, xray, "run", "-config", serverPath)
		waitTCP(t, server, serverPort)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("%s server logs:\n%s", security, server.logs.String())
			}
		})

		for _, budget := range []struct {
			name          string
			maxReuseTimes int
			newCarriers   int64
		}{
			{"default", 0, 0},
			{"maxReuseTimes=1", 1, 2},
		} {
			t.Run(security+"/"+budget.name, func(t *testing.T) {
				relay := startCountingRelay(t, serverPort)
				socksPort := freeTCPPort(t)
				clientPath := filepath.Join(workDir, fmt.Sprintf("client-%s-%d.json", security, budget.maxReuseTimes))
				writeConfig(t, clientPath, xrayMuxCoolTCPClientConfig(t, relay.port, socksPort, security, certificate, budget.maxReuseTimes))
				client := startReadyE2EClient(t, "xray", xray, []string{"run", "-config", clientPath}, socksPort)
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("client logs:\n%s", client.logs.String())
					}
				})

				// The held session's echo is the readiness check: it proves
				// the whole SOCKS-to-server-to-echo path.
				held := openMuxCoolSession(t, socksPort, tcpEcho)
				held.echo(t, "held, first carrier")
				before := relay.accepted.Load()
				for _, name := range []string{"second", "third"} {
					if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
						t.Fatalf("%s session: %v (server exited: %t)", name, err, serverExited(server))
					}
				}
				opened := relay.accepted.Load() - before
				held.echo(t, "held, after the other sessions")
				if opened != budget.newCarriers {
					t.Fatalf("two more sessions opened %d carrier(s), want %d", opened, budget.newCarriers)
				}
			})
		}
	}
}

// TestMuxCoolMaxReuseTimesOldServerProcess runs a client whose budget exceeds
// the old fixed 128 against Xray servers that predate the option. Sessions
// 129 and 130 carry IDs no earlier client sent on one carrier; the old server
// must serve them like any other. Session 131 then needs a new carrier.
func TestMuxCoolMaxReuseTimesOldServerProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level Mux.Cool reuse budget against old servers")
	}
	const budget = 130
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	for _, old := range muxCoolOldServers {
		t.Run(old.label, func(t *testing.T) {
			oldXray := buildXrayRevision(t, workDir, old.label, old.revision)
			serverPort := freeTCPPort(t)
			serverPath := filepath.Join(workDir, "server-"+old.label+".json")
			writeConfig(t, serverPath, xrayVLESSTCPConfig(t, true, serverPort, 0, "tls", "", certificate, privateKey, ""))
			server := startE2EProcess(t, oldXray, "run", "-config", serverPath)
			waitTCP(t, server, serverPort)
			relay := startCountingRelay(t, serverPort)
			socksPort := freeTCPPort(t)
			clientPath := filepath.Join(workDir, "client-"+old.label+".json")
			writeConfig(t, clientPath, xrayMuxCoolTCPClientConfig(t, relay.port, socksPort, "tls", certificate, budget))
			client := startReadyE2EClient(t, "xray", xray, []string{"run", "-config", clientPath}, socksPort)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("server logs:\n%s", server.logs.String())
					t.Logf("client logs:\n%s", client.logs.String())
				}
			})

			held := openMuxCoolSession(t, socksPort, tcpEcho)
			held.echo(t, "held, session 1")
			before := relay.accepted.Load()
			for session := 2; session <= budget; session++ {
				if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
					t.Fatalf("session %d: %v (server exited: %t)", session, err, serverExited(server))
				}
			}
			if opened := relay.accepted.Load() - before; opened != 0 {
				t.Fatalf("sessions 2-%d opened %d carrier(s), want all on the first", budget, opened)
			}
			if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
				t.Fatalf("session %d: %v (server exited: %t)", budget+1, err, serverExited(server))
			}
			if opened := relay.accepted.Load() - before; opened != 1 {
				t.Fatalf("session %d opened %d carrier(s), want 1", budget+1, opened)
			}
			held.echo(t, "held, after the budget ran out")
		})
	}
}

func xrayMuxCoolTCPClientConfig(t *testing.T, serverPort, socksPort int, security, certificate string, maxReuseTimes int) []byte {
	t.Helper()
	mux := map[string]any{"enabled": true, "concurrency": 8}
	if maxReuseTimes != 0 {
		mux["maxReuseTimes"] = maxReuseTimes
	}
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": serverPort,
				"users": []any{map[string]any{"id": testUUID, "encryption": "none"}},
			}}},
			"streamSettings": xrayVLESSTCPStreamSettings(false, security, certificate, "", ""),
			"mux":            mux,
		}},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// muxCoolSession is a SOCKS session the test keeps open across others.
type muxCoolSession struct {
	connection net.Conn
}

func openMuxCoolSession(t *testing.T, socksPort int, destination *net.TCPAddr) *muxCoolSession {
	t.Helper()
	connection, err := dialSOCKSTCPAttempt(socksPort, destination.IP.String(), destination.Port)
	if err != nil {
		t.Fatalf("open SOCKS session: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return &muxCoolSession{connection: connection}
}

func (s *muxCoolSession) echo(t *testing.T, payload string) {
	t.Helper()
	if err := s.connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.connection.Write([]byte(payload)); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(s.connection, response); err != nil {
		t.Fatalf("read echo of %q: %v", payload, err)
	}
	if !bytes.Equal(response, []byte(payload)) {
		t.Fatalf("echo = %q, want %q", response, payload)
	}
}

// buildXrayRevision builds ./main of an Xray revision from the local git
// object store into workDir.
func buildXrayRevision(t testing.TB, workDir, label, revision string) string {
	t.Helper()
	source := filepath.Join(workDir, label+"-source")
	binary := filepath.Join(workDir, "xray-"+label)
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := exec.Command("git", "-C", filepath.Join("..", ".."), "archive", revision)
	extract := exec.Command("tar", "-x", "-C", source)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	extract.Stdin, archive.Stderr, extract.Stderr = pipe, os.Stderr, os.Stderr
	if err := extract.Start(); err != nil {
		t.Fatal(err)
	}
	archiveErr := archive.Run() // closes the pipe, so tar ends either way
	extractErr := extract.Wait()
	if archiveErr != nil {
		t.Fatalf("git archive %s: %v", revision, archiveErr)
	}
	if extractErr != nil {
		t.Fatalf("extract %s: %v", revision, extractErr)
	}
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "./main")
	build.Dir = source
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", label, err, output)
	}
	return binary
}
