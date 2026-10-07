//go:build integration

package singmux_test

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Adapted to bdbac60e: the XHTTP HTTP/2 flow governor is off by default;
// XRAY_XHTTP_FLOW=on in the server's environment turns it on.

// xhttpFlowServerEnv is the server's environment with the governor switched
// as asked, whatever the test's own environment says.
func xhttpFlowServerEnv(governor bool) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "XRAY_XHTTP_FLOW=") || strings.HasPrefix(kv, "xray.xhttp.flow=") {
			continue
		}
		env = append(env, kv)
	}
	if governor {
		env = append(env, "XRAY_XHTTP_FLOW=on")
	}
	return env
}

// startE2EProcessWithEnv starts binary with env as its whole environment, as
// startE2EProcess does with the test's (copied from the pr17-fixes branch).
func startE2EProcessWithEnv(t testing.TB, env []string, binary string, arguments ...string) *e2eProcess {
	t.Helper()
	process := &e2eProcess{command: exec.Command(binary, arguments...), done: make(chan error, 1)}
	process.command.Env = env
	process.command.Stdout = &process.logs
	process.command.Stderr = &process.logs
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { process.done <- process.command.Wait() }()
	t.Cleanup(func() {
		if process.stopped.Load() || process.command.ProcessState != nil && process.command.ProcessState.Exited() {
			return
		}
		if process.command.Process != nil {
			_ = process.command.Process.Kill()
		}
		select {
		case <-process.done:
			process.stopped.Store(true)
		case <-time.After(3 * time.Second):
			t.Errorf("process %s did not exit", binary)
		}
	})
	return process
}

func startXHTTPFlowServer(t *testing.T, xray, configPath string, port int, governor bool) *e2eProcess {
	t.Helper()
	server := startE2EProcessWithEnv(t, xhttpFlowServerEnv(governor), xray, "run", "-config", configPath)
	waitTCP(t, server, port)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server (governor %t) logs:\n%s", governor, server.logs.String())
		}
	})
	return server
}

func xrayXHTTPFlowConfig(t testing.TB, server bool, serverPort, socksPort int, mode, certificate, privateKey string) []byte {
	t.Helper()
	stream := xrayTLSSettings(server, certificate, privateKey)
	stream["tlsSettings"].(map[string]any)["alpn"] = []string{"h2"}
	stream["network"] = "xhttp"
	stream["xhttpSettings"] = map[string]any{"path": "/xflow", "mode": mode}
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
		}}
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// xhttpFlowClient writes the client's configuration into dir and returns the
// binary and arguments that run it.
func xhttpFlowClient(t *testing.T, binaries e2eBinaries, peer, dir string, serverPort, socksPort int, mode, certificate string) (string, []string) {
	t.Helper()
	switch peer {
	case "xray":
		path := filepath.Join(dir, "client.json")
		writeConfig(t, path, xrayXHTTPFlowConfig(t, false, serverPort, socksPort, mode, certificate, ""))
		return binaries.xray, []string{"run", "-config", path}
	case "mihomo":
		path := filepath.Join(dir, "client.yaml")
		config := fmt.Sprintf(`socks-port: %d
allow-lan: false
mode: global
log-level: warning
proxies:
  - name: vless-xhttp
    type: vless
    server: 127.0.0.1
    port: %d
    uuid: %s
    network: xhttp
    tls: true
    alpn: [h2]
    servername: localhost
    skip-cert-verify: true
    xhttp-opts:
      path: /xflow
      mode: %s
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - vless-xhttp
`, socksPort, serverPort, testUUID, mode)
		writeConfig(t, path, []byte(config))
		return binaries.mihomo, []string{"-d", dir, "-f", path}
	}
	t.Fatalf("unsupported XHTTP client %q", peer)
	return "", nil
}

// serverH2Settings completes a TLS handshake with ALPN h2 on the server's
// port and returns the values of the first SETTINGS frame the server sends,
// before the client preface: an unauthenticated peer sees exactly these.
func serverH2Settings(t *testing.T, port int) map[uint16]uint32 {
	t.Helper()
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn := tls.Client(raw, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with the server: %v", err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("server negotiated %q, want h2", got)
	}
	for {
		var header [9]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			t.Fatalf("read server frame: %v", err)
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Fatalf("read server frame: %v", err)
		}
		if header[3] != 0x4 || header[4]&0x1 != 0 {
			continue
		}
		values := map[uint16]uint32{}
		for i := 0; i+6 <= len(payload); i += 6 {
			values[binary.BigEndian.Uint16(payload[i:])] = binary.BigEndian.Uint32(payload[i+2:])
		}
		return values
	}
}

const (
	h2SettingInitialWindowSize = 0x4
	h2SettingMaxFrameSize      = 0x5
)

// checkServerFlowSettings tells a governed server from a stock one by its
// SETTINGS: the governor advertises the protocol default frame size and
// initial window, stock net/http advertises 1 MiB for both.
func checkServerFlowSettings(t *testing.T, port int, governor bool) {
	t.Helper()
	values := serverH2Settings(t, port)
	frame, window := values[h2SettingMaxFrameSize], values[h2SettingInitialWindowSize]
	switch {
	case governor && (frame != 16384 || window != 1<<20):
		t.Fatalf("governed server advertises max frame size %d and initial window %d, want 16384 and Go's 1048576", frame, window)
	case !governor && (frame != 1<<20 || window != 1<<20):
		t.Fatalf("server with XRAY_XHTTP_FLOW=off advertises max frame size %d and initial window %d, want stock 1048576 for both", frame, window)
	}
}

// alpnRelay forwards loopback TCP to the server and records the ALPN
// protocols each client offers in its plaintext TLS ClientHello. The server
// accepts only h2, so a client that offers ALPN can only speak HTTP/2 to it.
type alpnRelay struct {
	port   int
	mu     sync.Mutex
	offers [][]string
}

func (r *alpnRelay) offered() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.offers)
}

func startALPNRelay(t testing.TB, serverPort int) *alpnRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &alpnRelay{port: listener.Addr().(*net.TCPAddr).Port}
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
			server, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			track(client)
			track(server)
			connections.Go(func() {
				var record [5]byte
				if _, err := io.ReadFull(client, record[:]); err != nil {
					_ = server.Close()
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(record[3:]))
				if _, err := io.ReadFull(client, body); err != nil {
					_ = server.Close()
					return
				}
				relay.mu.Lock()
				relay.offers = append(relay.offers, clientHelloALPN(body))
				relay.mu.Unlock()
				if _, err := server.Write(append(record[:], body...)); err != nil {
					return
				}
				_, _ = io.Copy(server, client)
				_ = server.(*net.TCPConn).CloseWrite()
			})
			connections.Go(func() {
				_, _ = io.Copy(client, server)
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

// clientHelloALPN returns the ALPN protocols in a ClientHello handshake
// message, or nil when it offers none or does not parse.
func clientHelloALPN(b []byte) []string {
	take := func(n int) []byte {
		if n > len(b) {
			b = nil
			return nil
		}
		v := b[:n]
		b = b[n:]
		return v
	}
	u8 := func() int {
		if v := take(1); v != nil {
			return int(v[0])
		}
		return 0
	}
	u16 := func() int {
		if v := take(2); v != nil {
			return int(binary.BigEndian.Uint16(v))
		}
		return 0
	}
	if h := take(4); h == nil || h[0] != 1 { // handshake type client_hello
		return nil
	}
	take(2 + 32)    // version, random
	take(u8())      // session id
	take(u16())     // cipher suites
	take(u8())      // compression methods
	b = take(u16()) // extensions
	for len(b) >= 4 {
		typ, data := u16(), take(u16())
		if typ != 16 || len(data) < 2 { // application_layer_protocol_negotiation
			continue
		}
		var protocols []string
		for list := data[2:]; len(list) > 0 && int(list[0]) < len(list); {
			protocols = append(protocols, string(list[1:1+list[0]]))
			list = list[1+list[0]:]
		}
		return protocols
	}
	return nil
}

// patternByte is the byte at offset i of every pattern transfer; it changes
// with each of the low 24 bits of the offset, so a lost, repeated or moved
// byte shows.
func patternByte(i int64) byte {
	return byte(i ^ i>>8 ^ i>>16)
}

func fillPattern(b []byte, offset int64) {
	for i := range b {
		b[i] = patternByte(offset + int64(i))
	}
}

// startPatternServer serves one request per connection: 'D' and a length
// asks it to send that many pattern bytes; 'U' and a length asks it to read
// and check that many and then answer one byte, 1 for intact.
func startPatternServer(t testing.TB) *net.TCPAddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	accepting := make(chan struct{})
	go func() {
		defer close(accepting)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Go(func() {
				defer conn.Close()
				var request [9]byte
				if _, err := io.ReadFull(conn, request[:]); err != nil {
					return
				}
				size := int64(binary.BigEndian.Uint64(request[1:]))
				buf := make([]byte, 64<<10)
				switch request[0] {
				case 'D':
					for sent := int64(0); sent < size; {
						n := min(int64(len(buf)), size-sent)
						fillPattern(buf[:n], sent)
						if _, err := conn.Write(buf[:n]); err != nil {
							return
						}
						sent += n
					}
				case 'U':
					intact := byte(1)
					for got := int64(0); got < size; {
						n, err := conn.Read(buf[:min(int64(len(buf)), size-got)])
						for i := range n {
							if buf[i] != patternByte(got+int64(i)) {
								intact = 0
							}
						}
						got += int64(n)
						if err != nil {
							return
						}
					}
					_, _ = conn.Write([]byte{intact})
				}
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepting
		connections.Wait()
	})
	return listener.Addr().(*net.TCPAddr)
}

// patternTransfer downloads ('D') or uploads ('U') size pattern bytes through
// SOCKS and checks every byte, returning how long the payload took.
func patternTransfer(socksPort int, server *net.TCPAddr, direction byte, size int64) (time.Duration, error) {
	conn, err := dialSOCKSTCPAttempt(socksPort, server.IP.String(), server.Port)
	if err != nil {
		return 0, fmt.Errorf("open SOCKS session: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
	request := binary.BigEndian.AppendUint64([]byte{direction}, uint64(size))
	if _, err := conn.Write(request); err != nil {
		return 0, fmt.Errorf("send request: %w", err)
	}
	buf := make([]byte, 64<<10)
	start := time.Now()
	switch direction {
	case 'D':
		for got := int64(0); got < size; {
			n, err := conn.Read(buf[:min(int64(len(buf)), size-got)])
			for i := range n {
				if buf[i] != patternByte(got+int64(i)) {
					return 0, fmt.Errorf("download byte %d differs", got+int64(i))
				}
			}
			got += int64(n)
			if err != nil && got < size {
				return 0, fmt.Errorf("download stopped at %d of %d bytes: %w", got, size, err)
			}
		}
	case 'U':
		for sent := int64(0); sent < size; {
			n := min(int64(len(buf)), size-sent)
			fillPattern(buf[:n], sent)
			if _, err := conn.Write(buf[:n]); err != nil {
				return 0, fmt.Errorf("upload stopped at %d of %d bytes: %w", sent, size, err)
			}
			sent += n
		}
		var status [1]byte
		if _, err := io.ReadFull(conn, status[:]); err != nil {
			return 0, fmt.Errorf("read upload status: %w", err)
		}
		if status[0] != 1 {
			return 0, errors.New("server saw a corrupted upload")
		}
	}
	return time.Since(start), nil
}

// runConcurrentEcho echoes a distinct random payload on each of sessions
// SOCKS connections at once and checks every byte that comes back.
func runConcurrentEcho(socksPort int, destination *net.TCPAddr, sessions, size int) error {
	errs := make(chan error, sessions)
	for range sessions {
		go func() {
			errs <- func() error {
				conn, err := dialSOCKSTCPAttempt(socksPort, destination.IP.String(), destination.Port)
				if err != nil {
					return fmt.Errorf("open SOCKS session: %w", err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
				payload := make([]byte, size)
				_, _ = rand.Read(payload)
				writeErr := make(chan error, 1)
				go func() {
					_, err := conn.Write(payload)
					writeErr <- err
				}()
				response := make([]byte, size)
				if _, err := io.ReadFull(conn, response); err != nil {
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

// TestXHTTPFlowProcess runs VLESS over XHTTP (TLS, HTTP/2) from real Xray and
// Mihomo clients to an Xray server with the HTTP/2 flow governor on
// (XRAY_XHTTP_FLOW=on) and off, the default on bdbac60e. sing-box has no XHTTP client.
// For each server it checks the SETTINGS an unauthenticated TLS peer sees on
// the port. For each client and mode it then echoes eight concurrent 1 MiB
// sessions and moves 16 MiB down and 16 MiB up on one session, byte for byte.
func TestXHTTPFlowProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level XHTTP flow governor")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)
	pattern := startPatternServer(t)

	for _, governor := range []bool{true, false} {
		serverPort := freeTCPPort(t)
		serverPath := filepath.Join(workDir, fmt.Sprintf("server-governor-%t.json", governor))
		writeConfig(t, serverPath, xrayXHTTPFlowConfig(t, true, serverPort, 0, "auto", certificate, privateKey))
		server := startXHTTPFlowServer(t, binaries.xray, serverPath, serverPort, governor)

		t.Run(fmt.Sprintf("governor=%t/settings", governor), func(t *testing.T) {
			checkServerFlowSettings(t, serverPort, governor)
		})
		for _, peer := range []string{"xray", "mihomo"} {
			for _, mode := range []string{"stream-up", "packet-up"} {
				t.Run(fmt.Sprintf("governor=%t/%s/%s", governor, peer, mode), func(t *testing.T) {
					dir := t.TempDir()
					socksPort := freeTCPPort(t)
					relay := startALPNRelay(t, serverPort)
					binary, arguments := xhttpFlowClient(t, binaries, peer, dir, relay.port, socksPort, mode, certificate)
					client := startReadyE2EClient(t, peer, binary, arguments, socksPort)
					t.Cleanup(func() {
						if t.Failed() {
							t.Logf("%s client logs:\n%s", peer, client.logs.String())
						}
					})
					waitSOCKSTCPForwarding(t, client, socksPort, tcpEcho)

					if err := runConcurrentEcho(socksPort, tcpEcho, 8, 1<<20); err != nil {
						t.Fatalf("concurrent echo: %v (server exited: %t)", err, serverExited(server))
					}
					for _, direction := range []byte{'D', 'U'} {
						if _, err := patternTransfer(socksPort, pattern, direction, 16<<20); err != nil {
							t.Fatalf("%c transfer: %v (server exited: %t)", direction, err, serverExited(server))
						}
					}
					if serverExited(server) {
						t.Fatal("server exited")
					}
					offers := relay.offered()
					if len(offers) == 0 {
						t.Fatal("no TLS connection reached the server")
					}
					for _, offer := range offers {
						if !slices.Contains(offer, "h2") {
							t.Fatalf("%s offered ALPN %q: not HTTP/2, the governor is not exercised", peer, offer)
						}
					}
					t.Logf("%s opened %d TLS connections offering ALPN %q", peer, len(offers), offers[0])
				})
			}
		}
		stopE2EProcess(t, server)
	}
}
