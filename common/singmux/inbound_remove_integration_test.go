//go:build integration

package singmux_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	removeInboundRemovedTag = "removed-in"
	removeInboundKeptTag    = "kept-in"
	removeInboundFlows      = 3
	// removeInboundEndWindow bounds how long a removed-side flow may live
	// after `xray api rmi` returns.
	removeInboundEndWindow = 5 * time.Second
	// removeInboundReAddWindow bounds the readiness poll for a new flow
	// through the same removed-side client after `xray api adi`.
	removeInboundReAddWindow = 15 * time.Second
)

// TestRemovedInboundConnectionsProcess removes an inbound through
// HandlerService (`xray api rmi`) while it holds live flows. The TCP worker's
// Close closed only its listener, and every connection the inbound had
// already accepted lived until its Process returned. Each cell runs one Xray
// server with two inbounds of the cell's protocol, security, and transport:
// removed-in, which the client under test uses, and kept-in, which an Xray
// client uses. After rmi every removed-side flow must end on the client side
// and at the echo fixture within removeInboundEndWindow while the kept-side
// flow keeps echoing; a new removed-side flow must not reach the fixture; and
// once `xray api adi` re-adds the same inbound, a new flow through the same
// removed-side client process must echo.
func TestRemovedInboundConnectionsProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level removed-inbound connection matrix")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	for _, cell := range removeInboundCells() {
		t.Run(cell.name(), func(t *testing.T) {
			removeInboundRunCell(t, workDir, binaries, certificate, privateKey, cell)
		})
	}
}

type removeInboundCell struct {
	protocol  string // vless or trojan
	peer      string // the removed-side client: xray, sing-box, or mihomo
	security  string // tls or reality
	transport string // raw, ws, grpc, or xhttp-stream-one (HTTP/2)
	carrier   string // direct, smux (sing-mux "smux", padding off), or muxcool
}

func (c removeInboundCell) name() string {
	parts := []string{c.protocol, c.peer, c.security}
	if c.transport != "raw" {
		parts = append(parts, c.transport)
	}
	return strings.Join(append(parts, c.carrier), "/")
}

func removeInboundCells() []removeInboundCell {
	var cells []removeInboundCell
	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		for _, carrier := range []string{"direct", "smux"} {
			cells = append(cells, removeInboundCell{protocol: "vless", peer: peer, security: "tls", transport: "raw", carrier: carrier})
		}
	}
	cells = append(cells,
		removeInboundCell{protocol: "vless", peer: "xray", security: "reality", transport: "raw", carrier: "direct"},
		removeInboundCell{protocol: "trojan", peer: "xray", security: "tls", transport: "raw", carrier: "direct"},
		// Mux.Cool is Xray's own multiplexer; sing-box and Mihomo do not
		// offer it as a client.
		removeInboundCell{protocol: "vless", peer: "xray", security: "tls", transport: "raw", carrier: "muxcool"},
	)
	// On these transports Process runs inside the transport's stream
	// handler, not on a connection the TCP worker accepted itself.
	for _, transport := range []string{"ws", "grpc", "xhttp-stream-one"} {
		cells = append(cells, removeInboundCell{protocol: "vless", peer: "xray", security: "tls", transport: transport, carrier: "direct"})
	}
	return cells
}

func removeInboundRunCell(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey string, cell removeInboundCell) {
	s := removeInboundStartScenario(t, workDir, binaries, certificate, privateKey, cell)
	removed := make([]*removeInboundFlow, removeInboundFlows)
	for i := range removed {
		removed[i] = s.openFlow(s.removedSOCKS, fmt.Sprintf("removed-%d", i+1))
	}
	kept := s.openFlow(s.keptSOCKS, "kept")
	s.api("rmi", "removing: "+removeInboundRemovedTag, removeInboundRemovedTag)
	s.assertRemovedFlowsEnd(removed, kept, time.Now())
	s.assertRemovedInboundUnreachable(kept)
	s.api("adi", "adding: "+removeInboundRemovedTag, s.addPath)
	s.assertReaddedInboundEchoes(removed, kept)
}

// removeInboundScenario is one cell's running topology: an Xray server with
// both inbounds and the API, the removed-side client, and the kept-side Xray
// client.
type removeInboundScenario struct {
	t             *testing.T
	name          string
	dir           string
	xray          string
	apiPort       int
	addPath       string
	server        *e2eProcess
	removedClient *e2eProcess
	removedSOCKS  int
	keptClient    *e2eProcess
	keptSOCKS     int
	echo          *removeInboundEcho
}

func removeInboundStartScenario(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey string, cell removeInboundCell) *removeInboundScenario {
	t.Helper()
	cellDir := filepath.Join(workDir, strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.MkdirAll(cellDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(cellDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(cellDir, "server.key"))
	s := &removeInboundScenario{
		t: t, name: cell.name(), dir: cellDir, xray: binaries.xray,
		apiPort: freeTCPPort(t), removedSOCKS: freeTCPUDPPort(t), keptSOCKS: freeTCPUDPPort(t),
		addPath: filepath.Join(cellDir, "removed-inbound.json"),
	}
	readiness := startTCPEcho(t).(*net.TCPAddr)
	s.echo = removeInboundStartEcho(t)
	realityTarget := ""
	if cell.security == "reality" {
		realityTarget = startRealityCoverServer(t, certificate, privateKey)
	}

	removedPort, keptPort := freeTCPPort(t), freeTCPPort(t)
	removedInbound := removeInboundInbound(cell, removeInboundRemovedTag, removedPort, certificate, privateKey, realityTarget)
	keptInbound := removeInboundInbound(cell, removeInboundKeptTag, keptPort, certificate, privateKey, realityTarget)
	serverPath := filepath.Join(cellDir, "server.json")
	writeConfig(t, serverPath, removeInboundMarshal(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"api": map[string]any{
			"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", s.apiPort), "services": []string{"HandlerService"},
		},
		"inbounds": []any{removedInbound, keptInbound},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	}))
	// The adi input re-adds removed-in exactly as the server first ran it.
	writeConfig(t, s.addPath, removeInboundMarshal(t, map[string]any{"inbounds": []any{removedInbound}}))

	s.server = startE2EProcess(t, binaries.xray, "run", "-config", serverPath)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		t.Logf("%s server logs:\n%s", s.name, s.server.logs.String())
		if s.removedClient != nil {
			t.Logf("%s removed-side %s client logs:\n%s", s.name, cell.peer, s.removedClient.logs.String())
		}
		if s.keptClient != nil {
			t.Logf("%s kept-side xray client logs:\n%s", s.name, s.keptClient.logs.String())
		}
	})
	waitTCP(t, s.server, removedPort)
	waitTCP(t, s.server, keptPort)
	waitTCP(t, s.server, s.apiPort)

	removedBinary, removedArgs, removedConfig := removeInboundClientConfig(t, binaries, cell, removedPort, s.removedSOCKS, certificate)
	removedPath := filepath.Join(cellDir, "removed-client"+configExtension(cell.peer, false))
	removedArgs = replaceConfigPath(removedArgs, removedPath)
	writeConfig(t, removedPath, removedConfig)
	s.removedClient = startReadyE2EClient(t, cell.peer, removedBinary, removedArgs, s.removedSOCKS)

	keptCell := cell
	keptCell.peer = "xray"
	keptPath := filepath.Join(cellDir, "kept-client.json")
	writeConfig(t, keptPath, removeInboundXrayClientConfig(t, keptCell, keptPort, s.keptSOCKS, certificate))
	s.keptClient = startReadyE2EClient(t, "xray", binaries.xray, []string{"run", "-config", keptPath}, s.keptSOCKS)

	// An open SOCKS port is not readiness: each client must carry a complete
	// SOCKS-to-server-to-echo round trip.
	waitSOCKSTCPForwarding(t, s.removedClient, s.removedSOCKS, readiness)
	waitSOCKSTCPForwarding(t, s.keptClient, s.keptSOCKS, readiness)
	return s
}

// openFlow opens a long-lived flow that must echo at once through exactly
// one upstream connection.
func (s *removeInboundScenario) openFlow(socksPort int, label string) *removeInboundFlow {
	t := s.t
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	flow, err := removeInboundDialFlow(socksPort, s.echo, label, deadline)
	if err != nil {
		t.Fatalf("%s: open %s flow: %v", s.name, label, err)
	}
	t.Cleanup(flow.close)
	if err := flow.roundTrip(deadline); err != nil {
		t.Fatalf("%s: %s flow did not echo: %v", s.name, label, err)
	}
	if upstreams := s.echo.upstreams(label); len(upstreams) != 1 {
		t.Fatalf("%s: %s flow reached the echo fixture through %d upstream connections, want 1", s.name, label, len(upstreams))
	}
	return flow
}

// api runs `xray api <command>` against the server. Both rmi and adi exit
// non-zero when the RPC fails; the wanted line names the inbound they acted
// on.
func (s *removeInboundScenario) api(command, want string, arguments ...string) {
	t := s.t
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	arguments = append([]string{"api", command, fmt.Sprintf("--server=127.0.0.1:%d", s.apiPort)}, arguments...)
	process := exec.CommandContext(ctx, s.xray, arguments...)
	// rmi reads an argument as a tag only when no file of that name exists.
	process.Dir = s.dir
	output, err := process.CombinedOutput()
	if err != nil || !strings.Contains(string(output), want) {
		t.Fatalf("%s: xray %s did not succeed with %q (exit: %v):\n%s", s.name, strings.Join(arguments, " "), want, err, output)
	}
	t.Logf("%s: xray %s: %s", s.name, strings.Join(arguments, " "), strings.ReplaceAll(strings.TrimSpace(string(output)), "\n", "; "))
}

// assertRemovedFlowsEnd requires every removed-side flow to end on the client
// side (a read returns EOF or a connection error; an expired read deadline
// proves nothing) and at the echo fixture within removeInboundEndWindow of
// rmi, while the kept-side flow keeps echoing fresh lines during the window
// and after it.
func (s *removeInboundScenario) assertRemovedFlowsEnd(removed []*removeInboundFlow, kept *removeInboundFlow, removedAt time.Time) {
	t := s.t
	deadline := removedAt.Add(removeInboundEndWindow)
	stopKept := removeInboundKeepEchoing(kept)
	ends := make([]chan removeInboundEnd, len(removed))
	for i, flow := range removed {
		ends[i] = make(chan removeInboundEnd, 1)
		go func() { ends[i] <- flow.awaitEnd(deadline) }()
	}
	for i := range removed {
		end := <-ends[i]
		switch {
		case end.err != nil:
			t.Logf("%s: removed-side flow %d ended %s after rmi: %v", s.name, i+1, end.at.Sub(removedAt).Round(time.Millisecond), end.err)
		case end.echoes > 0:
			t.Errorf("%s: removed-side flow %d still echoes %s after rmi (%d fresh lines echoed after rmi, the last %s after it)",
				s.name, i+1, removeInboundEndWindow, end.echoes, end.at.Sub(removedAt).Round(time.Millisecond))
		default:
			t.Errorf("%s: removed-side flow %d neither ended nor echoed within %s after rmi; only read deadlines expired", s.name, i+1, removeInboundEndWindow)
		}
	}
	for i, flow := range removed {
		if !s.echo.upstreams(flow.label)[0].awaitClosed(deadline) {
			t.Errorf("%s: the echo fixture still holds removed-side flow %d's upstream connection open %s after rmi", s.name, i+1, removeInboundEndWindow)
		}
	}
	if echoes, err := stopKept(); err != nil {
		t.Errorf("%s: kept-side flow stopped echoing during the %s after rmi (after %d fresh lines): %v", s.name, removeInboundEndWindow, echoes, err)
	}
	if err := kept.roundTrip(time.Now().Add(removeInboundEndWindow)); err != nil {
		t.Errorf("%s: kept-side flow stopped echoing after the removed-side flows were checked: %v", s.name, err)
	}
	if upstreams := s.echo.upstreams(kept.label); len(upstreams) != 1 || upstreams[0].isClosed() {
		t.Errorf("%s: the kept-side flow's upstream connection did not survive the rmi of %s", s.name, removeInboundRemovedTag)
	}
	if t.Failed() {
		t.FailNow()
	}
}

// assertRemovedInboundUnreachable requires a new flow through the
// removed-side client to stay away from the echo fixture: the inbound's port
// is closed and none of its carriers may still serve streams.
func (s *removeInboundScenario) assertRemovedInboundUnreachable(kept *removeInboundFlow) {
	t := s.t
	acceptedBefore := s.echo.accepted.Load()
	deadline := time.Now().Add(3 * time.Second)
	flow, err := removeInboundDialFlow(s.removedSOCKS, s.echo, "removed-after-rmi", deadline)
	if err == nil {
		t.Cleanup(flow.close)
		if err = flow.roundTrip(deadline); err == nil {
			t.Fatalf("%s: a new removed-side flow echoed through the server after rmi", s.name)
		}
	}
	if accepted := s.echo.accepted.Load() - acceptedBefore; accepted != 0 {
		t.Fatalf("%s: a new removed-side flow reached the echo fixture after rmi (%d new upstream connection(s)); flow error: %v", s.name, accepted, err)
	}
	t.Logf("%s: a new removed-side flow did not reach the echo fixture after rmi: %v", s.name, err)
	if err := kept.roundTrip(time.Now().Add(removeInboundEndWindow)); err != nil {
		t.Fatalf("%s: kept-side flow stopped echoing after the removed-side flow was refused: %v", s.name, err)
	}
}

// assertReaddedInboundEchoes polls, as readiness, for a new flow that echoes
// through the same removed-side client process after adi, then requires the
// old flows to stay ended and the kept-side flow to keep echoing.
func (s *removeInboundScenario) assertReaddedInboundEchoes(removed []*removeInboundFlow, kept *removeInboundFlow) {
	t := s.t
	deadline := time.Now().Add(removeInboundReAddWindow)
	for attempt := 1; ; attempt++ {
		attemptDeadline := removeInboundEarlier(deadline, time.Now().Add(2*time.Second))
		flow, err := removeInboundDialFlow(s.removedSOCKS, s.echo, fmt.Sprintf("readded-%d", attempt), attemptDeadline)
		if err == nil {
			t.Cleanup(flow.close)
			if err = flow.roundTrip(attemptDeadline); err == nil {
				t.Logf("%s: a new removed-side flow echoed on attempt %d after adi", s.name, attempt)
				break
			}
			flow.close()
		}
		if serverExited(s.removedClient) {
			t.Fatalf("%s: the removed-side client exited before a flow echoed after adi: %v", s.name, err)
		}
		if serverExited(s.server) {
			t.Fatalf("%s: the server exited before a removed-side flow echoed after adi: %v", s.name, err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("%s: no new flow through the same removed-side client echoed within %s of adi: %v", s.name, removeInboundReAddWindow, err)
		}
		time.Sleep(25 * time.Millisecond) // interval between readiness attempts
	}
	for i, flow := range removed {
		if _, err := flow.readLine(time.Now().Add(250 * time.Millisecond)); err == nil || removeInboundTimeout(err) {
			t.Errorf("%s: removed-side flow %d no longer reads as ended after adi: %v", s.name, i+1, err)
		}
		if upstreams := s.echo.upstreams(flow.label); len(upstreams) != 1 || !upstreams[0].isClosed() {
			t.Errorf("%s: removed-side flow %d's upstream reopened or stayed open after adi (%d upstream connection(s))", s.name, i+1, len(upstreams))
		}
	}
	if err := kept.roundTrip(time.Now().Add(removeInboundEndWindow)); err != nil {
		t.Errorf("%s: kept-side flow stopped echoing after adi: %v", s.name, err)
	}
}

// removeInboundKeepEchoing round-trips fresh lines on flow until the returned
// stop function is called; stop reports how many echoed and the first error.
func removeInboundKeepEchoing(flow *removeInboundFlow) func() (int, error) {
	type result struct {
		echoes int
		err    error
	}
	stop := make(chan struct{})
	done := make(chan result, 1)
	go func() {
		var r result
		for {
			if err := flow.roundTrip(time.Now().Add(removeInboundEndWindow)); err != nil {
				r.err = err
				done <- r
				return
			}
			r.echoes++
			select {
			case <-stop:
				done <- r
				return
			case <-time.After(200 * time.Millisecond): // pace between kept-side round trips
			}
		}
	}()
	return func() (int, error) {
		close(stop)
		r := <-done
		return r.echoes, r.err
	}
}

func removeInboundInbound(cell removeInboundCell, tag string, port int, certificate, privateKey, realityTarget string) map[string]any {
	settings := map[string]any{"clients": []any{map[string]any{"password": testPassword}}}
	if cell.protocol == "vless" {
		settings = map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": testUUID}}}
	}
	return map[string]any{
		"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": cell.protocol,
		"settings":       settings,
		"streamSettings": removeInboundStreamSettings(true, cell, certificate, privateKey, realityTarget),
	}
}

func removeInboundStreamSettings(server bool, cell removeInboundCell, certificate, privateKey, realityTarget string) map[string]any {
	if cell.security == "reality" {
		return xrayVLESSTCPStreamSettings(server, "reality", certificate, privateKey, realityTarget)
	}
	stream := xrayTLSSettings(server, certificate, privateKey)
	switch cell.transport {
	case "raw":
	case "ws":
		stream["network"] = "ws"
		stream["wsSettings"] = map[string]any{"path": "/removed-inbound-ws"}
	case "grpc":
		stream["network"] = "grpc"
		stream["grpcSettings"] = map[string]any{"serviceName": "removedinbound", "multiMode": false}
	case "xhttp-stream-one":
		stream["tlsSettings"].(map[string]any)["alpn"] = []string{"h2"}
		stream["network"] = "xhttp"
		stream["xhttpSettings"] = map[string]any{"path": "/removed-inbound-xhttp", "mode": "stream-one"}
	default:
		panic("unknown removed-inbound transport " + cell.transport)
	}
	return stream
}

func removeInboundClientConfig(t *testing.T, binaries e2eBinaries, cell removeInboundCell, serverPort, socksPort int, certificate string) (string, []string, []byte) {
	t.Helper()
	if cell.peer == "xray" {
		return binaries.xray, []string{"run", "-config", "client.json"}, removeInboundXrayClientConfig(t, cell, serverPort, socksPort, certificate)
	}
	if cell.protocol != "vless" || cell.security != "tls" || cell.transport != "raw" || cell.carrier == "muxcool" {
		t.Fatalf("%s: no %s client configuration for this cell", cell.name(), cell.peer)
	}
	binary, arguments, config := vlessTCPClientConfig(t, binaries, cell.peer, serverPort, socksPort, "tls", "", certificate)
	if cell.carrier == "smux" {
		config = removeInboundWithSMUX(t, cell.peer, config)
	}
	return binary, arguments, config
}

func removeInboundXrayClientConfig(t *testing.T, cell removeInboundCell, serverPort, socksPort int, certificate string) []byte {
	t.Helper()
	settings := map[string]any{"servers": []any{map[string]any{
		"address": "127.0.0.1", "port": serverPort, "password": testPassword,
	}}}
	if cell.protocol == "vless" {
		settings = map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": serverPort,
			"users": []any{map[string]any{"id": testUUID, "encryption": "none"}},
		}}}
	}
	outbound := map[string]any{
		"protocol":       cell.protocol,
		"settings":       settings,
		"streamSettings": removeInboundStreamSettings(false, cell, certificate, "", ""),
	}
	switch cell.carrier {
	case "direct":
	case "smux":
		outbound["smux"] = map[string]any{"enabled": true, "protocol": "smux", "maxConnections": 1, "padding": false}
	case "muxcool":
		// Concurrency 8 lets the readiness check and every flow share one carrier.
		outbound["mux"] = map[string]any{"enabled": true, "concurrency": 8}
	default:
		t.Fatalf("%s: unknown carrier %q", cell.name(), cell.carrier)
	}
	return removeInboundMarshal(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []any{outbound},
	})
}

func removeInboundWithSMUX(t *testing.T, peer string, config []byte) []byte {
	t.Helper()
	if peer == "sing-box" {
		var decoded map[string]any
		if err := json.Unmarshal(config, &decoded); err != nil {
			t.Fatal(err)
		}
		outbound := decoded["outbounds"].([]any)[0].(map[string]any)
		outbound["multiplex"] = map[string]any{"enabled": true, "protocol": "smux", "max_connections": 1, "padding": false}
		return removeInboundMarshal(t, decoded)
	}
	const anchor = "proxy-groups:\n"
	if count := bytes.Count(config, []byte(anchor)); count != 1 {
		t.Fatalf("Mihomo client configuration holds %q %d times, want once:\n%s", anchor, count, config)
	}
	return bytes.Replace(config, []byte(anchor), []byte("    smux:\n      enabled: true\n      protocol: smux\n      max-connections: 1\n      padding: false\n"+anchor), 1)
}

func removeInboundMarshal(t *testing.T, config map[string]any) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// removeInboundEcho echoes newline-terminated lines. It names each accepted
// upstream connection by the label of its first line ("<label>#<seq>") and
// records when that connection ends.
type removeInboundEcho struct {
	address  *net.TCPAddr
	listener net.Listener
	accepted atomic.Int64
	workers  sync.WaitGroup
	mu       sync.Mutex
	stopped  bool
	open     map[net.Conn]struct{}
	labels   map[string][]*removeInboundUpstream
}

type removeInboundUpstream struct {
	closed chan struct{}
}

func (u *removeInboundUpstream) isClosed() bool {
	select {
	case <-u.closed:
		return true
	default:
		return false
	}
}

// awaitClosed reports whether the upstream connection ended by deadline.
func (u *removeInboundUpstream) awaitClosed(deadline time.Time) bool {
	if u.isClosed() {
		return true
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-u.closed:
		return true
	case <-timer.C:
		return u.isClosed()
	}
}

func removeInboundStartEcho(t *testing.T) *removeInboundEcho {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echo := &removeInboundEcho{
		address: listener.Addr().(*net.TCPAddr), listener: listener,
		open: make(map[net.Conn]struct{}), labels: make(map[string][]*removeInboundUpstream),
	}
	echo.workers.Add(1)
	go echo.accept()
	t.Cleanup(echo.close)
	return echo
}

func (e *removeInboundEcho) accept() {
	defer e.workers.Done()
	for {
		connection, err := e.listener.Accept()
		if err != nil {
			return
		}
		e.accepted.Add(1)
		e.mu.Lock()
		if e.stopped {
			e.mu.Unlock()
			_ = connection.Close()
			continue
		}
		e.open[connection] = struct{}{}
		e.workers.Add(1)
		e.mu.Unlock()
		go e.serve(connection)
	}
}

func (e *removeInboundEcho) serve(connection net.Conn) {
	defer e.workers.Done()
	var upstream *removeInboundUpstream
	defer func() {
		_ = connection.Close()
		e.mu.Lock()
		delete(e.open, connection)
		e.mu.Unlock()
		if upstream != nil {
			close(upstream.closed)
		}
	}()
	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if upstream == nil {
			// Registered before the echo, so a client holding the echo
			// always finds its upstream.
			label, _, _ := strings.Cut(line, "#")
			upstream = &removeInboundUpstream{closed: make(chan struct{})}
			e.mu.Lock()
			e.labels[label] = append(e.labels[label], upstream)
			e.mu.Unlock()
		}
		if _, err := io.WriteString(connection, line); err != nil {
			return
		}
	}
}

func (e *removeInboundEcho) upstreams(label string) []*removeInboundUpstream {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*removeInboundUpstream(nil), e.labels[label]...)
}

func (e *removeInboundEcho) close() {
	_ = e.listener.Close()
	e.mu.Lock()
	e.stopped = true
	for connection := range e.open {
		_ = connection.Close()
	}
	e.mu.Unlock()
	e.workers.Wait()
}

// removeInboundFlow is one SOCKS connection to the echo fixture. Every line
// it writes is unique.
type removeInboundFlow struct {
	label   string
	conn    net.Conn
	pending []byte
	seq     int
}

// removeInboundDialFlow opens a SOCKS CONNECT to the echo fixture; deadline
// bounds the dial and the SOCKS exchange.
func removeInboundDialFlow(socksPort int, echo *removeInboundEcho, label string, deadline time.Time) (*removeInboundFlow, error) {
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS: %w", err)
	}
	_ = connection.SetDeadline(deadline)
	if err := socksGreeting(connection); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("SOCKS greeting: %w", err)
	}
	request := append([]byte{5, 1, 0, 1}, echo.address.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(echo.address.Port))
	if _, err := connection.Write(request); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("SOCKS connect request: %w", err)
	}
	if err := readSOCKSReply(connection); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("SOCKS connect reply: %w", err)
	}
	_ = connection.SetDeadline(time.Time{})
	return &removeInboundFlow{label: label, conn: connection}, nil
}

func (f *removeInboundFlow) close() { _ = f.conn.Close() }

func (f *removeInboundFlow) nextLine() string {
	f.seq++
	return fmt.Sprintf("%s#%d\n", f.label, f.seq)
}

func (f *removeInboundFlow) write(line string, deadline time.Time) error {
	_ = f.conn.SetWriteDeadline(deadline)
	_, err := io.WriteString(f.conn, line)
	return err
}

// readLine returns the next echoed line. Bytes read before a deadline expires
// stay pending for the next call.
func (f *removeInboundFlow) readLine(deadline time.Time) (string, error) {
	_ = f.conn.SetReadDeadline(deadline)
	buffer := make([]byte, 1024)
	for {
		if end := bytes.IndexByte(f.pending, '\n'); end >= 0 {
			line := string(f.pending[:end+1])
			f.pending = f.pending[end+1:]
			return line, nil
		}
		n, err := f.conn.Read(buffer)
		f.pending = append(f.pending, buffer[:n]...)
		if err != nil && bytes.IndexByte(f.pending, '\n') < 0 {
			return "", err
		}
	}
}

func (f *removeInboundFlow) roundTrip(deadline time.Time) error {
	want := f.nextLine()
	if err := f.write(want, deadline); err != nil {
		return fmt.Errorf("write %q: %w", want, err)
	}
	got, err := f.readLine(deadline)
	if err != nil {
		return fmt.Errorf("read echo of %q: %w", want, err)
	}
	if got != want {
		return fmt.Errorf("echo %q, want %q", got, want)
	}
	return nil
}

// removeInboundEnd is what a removed-side flow showed after rmi: the read
// error that ended it, or the fresh lines it still echoed.
type removeInboundEnd struct {
	err    error
	echoes int
	at     time.Time // when it ended, or when it last echoed
}

// awaitEnd keeps writing fresh lines until a read ends the flow or deadline
// passes. Between writes it reads without writing, so an end shows up even
// when the flow would still accept writes.
func (f *removeInboundFlow) awaitEnd(deadline time.Time) removeInboundEnd {
	var result removeInboundEnd
	observe := func(wait time.Duration) bool {
		_, err := f.readLine(removeInboundEarlier(deadline, time.Now().Add(wait)))
		switch {
		case err == nil:
			result.echoes++
			result.at = time.Now()
		case !removeInboundTimeout(err):
			result.err = err
			result.at = time.Now()
			return true
		}
		return false
	}
	for time.Now().Before(deadline) {
		// A failed write proves nothing by itself; the reads below decide.
		_ = f.write(f.nextLine(), deadline)
		if observe(time.Second) || observe(250*time.Millisecond) {
			return result
		}
	}
	return result
}

func removeInboundTimeout(err error) bool {
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

func removeInboundEarlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
