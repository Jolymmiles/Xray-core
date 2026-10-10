//go:build integration

package singmux_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestXHTTPMuxCoolProcess runs Mux.Cool TCP sessions from an Xray client over
// XHTTP to an Xray server, as allowed since the fork dropped upstream's
// XUDP-only rule for XHTTP. Only Xray clients speak Mux.Cool; sing-box and
// Mihomo use their own multiplexers and are covered by the SMUX matrices.
//
// A counting relay between client and server shows the server's idle
// downlink KeepAlive: frames flow while every session is quiet in packet-up
// and stream-up when the server asks for them, and nothing flows without the
// option or in stream-one, whose downlink is not a response of its own.
func TestXHTTPMuxCoolProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level XHTTP Mux.Cool")
	}
	const (
		keepAlivePadding = 200
		idleWindow       = 3500 * time.Millisecond
		// One KeepAlive frame carries at least its padding; TLS and HTTP/2
		// framing only add to that. Flow-control and TLS bookkeeping a peer
		// may still send during the window stays far below one frame.
		keepAliveFloor = 2 * keepAlivePadding
	)
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	for _, keepAlive := range []bool{true, false} {
		serverPort := freeTCPPort(t)
		serverPath := filepath.Join(workDir, fmt.Sprintf("server-keepalive-%t.json", keepAlive))
		writeConfig(t, serverPath, xrayXHTTPMuxCoolConfig(t, true, serverPort, 0, "auto", keepAlive, keepAlivePadding, certificate, privateKey))
		server := startE2EProcess(t, xray, "run", "-config", serverPath)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("server (keepalive %t) logs:\n%s", keepAlive, server.logs.String())
			}
		})

		for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
			t.Run(fmt.Sprintf("keepalive=%t/%s", keepAlive, mode), func(t *testing.T) {
				relay := startCountingRelay(t, serverPort)
				socksPort := freeTCPPort(t)
				clientPath := filepath.Join(workDir, fmt.Sprintf("client-%t-%s.json", keepAlive, mode))
				writeConfig(t, clientPath, xrayXHTTPMuxCoolConfig(t, false, relay.port, socksPort, mode, false, 0, certificate, ""))
				client := startReadyE2EClient(t, "xray", xray, []string{"run", "-config", clientPath}, socksPort)
				waitSOCKSTCPForwarding(t, client, socksPort, tcpEcho)

				if err := runConcurrentMuxCoolEcho(socksPort, tcpEcho, 8, 64<<10); err != nil {
					t.Fatalf("concurrent Mux.Cool sessions: %v (server exited: %t)", err, serverExited(server))
				}

				idleBytes, err := runIdleMuxCoolSession(socksPort, tcpEcho, relay, idleWindow)
				if err != nil {
					t.Fatalf("session across an idle downlink: %v (server exited: %t)", err, serverExited(server))
				}
				poked := keepAlive && mode != "stream-one"
				switch {
				case poked && idleBytes < keepAliveFloor:
					t.Fatalf("server sent %d bytes during %v of silence, want at least %d from KeepAlive frames", idleBytes, idleWindow, keepAliveFloor)
				case !poked && idleBytes >= keepAlivePadding:
					t.Fatalf("server sent %d bytes during %v of silence without KeepAlive", idleBytes, idleWindow)
				}
				t.Logf("server sent %d bytes during %v of silence", idleBytes, idleWindow)
			})
		}
	}
}

func xrayXHTTPMuxCoolConfig(t *testing.T, server bool, serverPort, socksPort int, mode string, keepAlive bool, keepAlivePadding int, certificate, privateKey string) []byte {
	t.Helper()
	xhttp := map[string]any{"path": "/mux", "mode": mode}
	if keepAlive {
		xhttp["muxKeepAliveSecs"] = "1-1"
		xhttp["muxKeepAliveBytes"] = fmt.Sprintf("%d-%d", keepAlivePadding, keepAlivePadding)
	}
	stream := xrayTLSSettings(server, certificate, privateKey)
	stream["network"] = "xhttp"
	stream["xhttpSettings"] = xhttp
	config := map[string]any{"log": map[string]any{"loglevel": "warning"}}
	if server {
		config["inbounds"] = []any{map[string]any{
			"listen": "127.0.0.1", "port": serverPort, "protocol": "vless",
			"settings":       map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": testUUID}}},
			"streamSettings": stream,
		}}
		config["outbounds"] = []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}}
	} else {
		config["inbounds"] = []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}}
		config["outbounds"] = []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": serverPort,
				"users": []any{map[string]any{"id": testUUID, "encryption": "none"}},
			}}},
			"streamSettings": stream,
			"mux":            map[string]any{"enabled": true, "concurrency": 8},
		}}
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// countingRelay forwards loopback TCP to the server and counts the
// connections it accepts and the bytes the server sends back.
type countingRelay struct {
	port       int
	accepted   atomic.Int64
	downstream atomic.Int64
}

func startCountingRelay(t *testing.T, serverPort int) *countingRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &countingRelay{port: listener.Addr().(*net.TCPAddr).Port}
	var connections sync.WaitGroup
	var mu sync.Mutex
	open := map[net.Conn]struct{}{}
	track := func(conn net.Conn) {
		mu.Lock()
		open[conn] = struct{}{}
		mu.Unlock()
	}
	accepting := make(chan struct{})
	go func() {
		defer close(accepting)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			relay.accepted.Add(1)
			server, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			track(client)
			track(server)
			connections.Go(func() {
				_, _ = io.Copy(server, client)
				_ = server.(*net.TCPConn).CloseWrite()
			})
			connections.Go(func() {
				_, _ = io.Copy(countingWriter{client, &relay.downstream}, server)
				_ = client.(*net.TCPConn).CloseWrite()
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepting
		mu.Lock()
		for conn := range open {
			_ = conn.Close()
		}
		mu.Unlock()
		connections.Wait()
	})
	return relay
}

type countingWriter struct {
	io.Writer
	count *atomic.Int64
}

func (w countingWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	w.count.Add(int64(n))
	return n, err
}

// runConcurrentMuxCoolEcho echoes a distinct random payload on each of
// sessions SOCKS connections at once and checks every byte that comes back.
func runConcurrentMuxCoolEcho(socksPort int, destination *net.TCPAddr, sessions, size int) error {
	errs := make(chan error, sessions)
	for range sessions {
		go func() {
			errs <- func() error {
				connection, err := dialSOCKSTCPAttempt(socksPort, destination.IP.String(), destination.Port)
				if err != nil {
					return fmt.Errorf("open SOCKS session: %w", err)
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
				payload := make([]byte, size)
				_, _ = rand.Read(payload)
				writeErr := make(chan error, 1)
				go func() {
					_, err := connection.Write(payload)
					writeErr <- err
				}()
				response := make([]byte, size)
				if _, err := io.ReadFull(connection, response); err != nil {
					return fmt.Errorf("read echo: %w", err)
				}
				if err := <-writeErr; err != nil {
					return fmt.Errorf("write payload: %w", err)
				}
				if !bytes.Equal(response, payload) {
					return errors.New("echoed payload differs from the one sent")
				}
				return nil
			}()
		}()
	}
	var first error
	for range sessions {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	return first
}

// runIdleMuxCoolSession echoes on one session, keeps every session quiet for
// idle, echoes again on the same session, and reports how many bytes the
// server sent while all was quiet.
func runIdleMuxCoolSession(socksPort int, destination *net.TCPAddr, relay *countingRelay, idle time.Duration) (int64, error) {
	connection, err := dialSOCKSTCPAttempt(socksPort, destination.IP.String(), destination.Port)
	if err != nil {
		return 0, fmt.Errorf("open SOCKS session: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(idle + 20*time.Second))
	echo := func(payload []byte) error {
		if _, err := connection.Write(payload); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(connection, response); err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if !bytes.Equal(response, payload) {
			return fmt.Errorf("echo %q, want %q", response, payload)
		}
		return nil
	}
	if err := echo([]byte("before-idle")); err != nil {
		return 0, err
	}
	before := relay.downstream.Load()
	time.Sleep(idle) // the scenario itself: no session sends anything
	idleBytes := relay.downstream.Load() - before
	if err := echo([]byte("after-idle")); err != nil {
		return idleBytes, err
	}
	return idleBytes, nil
}
