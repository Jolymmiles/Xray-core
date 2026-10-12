//go:build integration

package singmux_test

import (
	"bufio"
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The victim keeps the shared harness credentials (testUUID, testPassword), so
// the existing per-peer client builders configure it unchanged; the bystander
// gets credentials of its own.
const (
	revokeInboundTag        = "revoke-in"
	revokeVictimEmail       = "victim@revoke.test"
	revokeBystanderEmail    = "bystander@revoke.test"
	revokeBystanderUUID     = "4a0e9c3d-2b7f-4e61-9d58-71c2f0b6a913"
	revokeBystanderPassword = "xray-revoke-bystander-password"
	revokeVisionFlow        = "xtls-rprx-vision"
	revokeVictimFlows       = 3
	revokeDeadline          = 5 * time.Second
)

// The server's debug records of Vision's direct-copy transition: the client's
// CommandPaddingDirect (2) arriving, and the server sending its own. After
// them both directions copy raw bytes outside the TLS layer.
var (
	revokeVisionDirectIn  = regexp.MustCompile(`Xtls Unpadding new block, content \d+ padding \d+ command 2`)
	revokeVisionDirectOut = regexp.MustCompile(`XtlsPadding \d+ \d+ 2\b`)
)

// TestRemovedUserConnectionsProcessMatrix removes a user through HandlerService
// while the user holds live flows (upstream XTLS/Xray-core#5844: a removed
// user kept every open connection, and a 1 GB quota user used 18 GB). Each
// cell runs one Xray server whose inbound holds a victim and a bystander. The
// victim's client, the peer under test, holds three flows to an echo fixture
// that records every upstream connection; an Xray bystander client holds one.
// After `xray api rmu` every victim flow must end on the client side and at
// the fixture within five seconds, a new victim flow must not reach the
// fixture, and the bystander must keep echoing. After `xray api adu` re-adds
// the victim, a new flow through the same victim client process must echo.
func TestRemovedUserConnectionsProcessMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level removed-user connection matrix")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	for _, cell := range revokeCells() {
		t.Run(cell.name(), func(t *testing.T) {
			runRevokeCell(t, workDir, binaries, certificate, privateKey, cell)
		})
	}
}

type revokeCell struct {
	protocol string // vless or trojan
	peer     string // the victim's client: xray, sing-box, or mihomo
	security string // tls or reality
	carrier  string // direct, smux (sing-mux "smux", padding off), or muxcool
	flow     string // "" or xtls-rprx-vision
}

func (c revokeCell) name() string {
	name := strings.Join([]string{c.protocol, c.peer, c.security, c.carrier}, "/")
	if c.flow != "" {
		name += "/vision"
	}
	return name
}

func revokeCells() []revokeCell {
	peers := []string{"xray", "sing-box", "mihomo"}
	var cells []revokeCell
	for _, peer := range peers {
		for _, security := range []string{"tls", "reality"} {
			for _, carrier := range []string{"direct", "smux"} {
				cells = append(cells, revokeCell{protocol: "vless", peer: peer, security: security, carrier: carrier})
			}
		}
		for _, carrier := range []string{"direct", "smux"} {
			cells = append(cells, revokeCell{protocol: "trojan", peer: peer, security: "tls", carrier: carrier})
		}
	}
	// Mux.Cool is Xray's own multiplexer; sing-box and Mihomo do not offer it
	// as a client.
	cells = append(cells, revokeCell{protocol: "vless", peer: "xray", security: "tls", carrier: "muxcool"})
	// Vision runs on a direct carrier only: Vision over a multiplexer is not a
	// supported combination, so no Vision cell uses smux or Mux.Cool.
	for _, peer := range peers {
		for _, security := range []string{"tls", "reality"} {
			cells = append(cells, revokeCell{protocol: "vless", peer: peer, security: security, carrier: "direct", flow: revokeVisionFlow})
		}
	}
	return cells
}

func runRevokeCell(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey string, cell revokeCell) {
	s := startRevokeScenario(t, workDir, binaries, certificate, privateKey, cell)
	victims := s.openVictimFlows()
	bystander := s.openFlow(s.bystanderSOCKS, s.bystanderEcho, "bystander")
	s.api("rmu", "Removed 1 user(s) in total.", "-tag="+revokeInboundTag, revokeVictimEmail)
	s.assertVictimFlowsEnd(victims, bystander, time.Now())
	s.assertRemovedVictimRejected(bystander)
	s.api("adu", "Added 1 user(s) in total.", s.addUserPath)
	s.assertReaddedVictimEchoes(victims, bystander)
}

// revokeScenario is one cell's running topology: an Xray server, the victim
// client (through a counting relay on mux carriers), and the bystander client.
type revokeScenario struct {
	t              *testing.T
	cell           revokeCell
	name           string
	xray           string
	apiPort        int
	addUserPath    string
	server         *e2eProcess
	victim         *e2eProcess
	victimSOCKS    int
	victimEcho     *revokeEchoServer
	relay          *countingRelay
	bystanderSOCKS int
	bystanderEcho  *revokeEchoServer
}

func startRevokeScenario(t *testing.T, workDir string, binaries e2eBinaries, certificate, privateKey string, cell revokeCell) *revokeScenario {
	t.Helper()
	cellDir := filepath.Join(workDir, strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.MkdirAll(cellDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificate = copyScenarioFile(t, certificate, filepath.Join(cellDir, "server.crt"))
	privateKey = copyScenarioFile(t, privateKey, filepath.Join(cellDir, "server.key"))
	s := &revokeScenario{
		t: t, cell: cell, name: cell.name(), xray: binaries.xray,
		apiPort: freeTCPPort(t), victimSOCKS: freeTCPUDPPort(t), bystanderSOCKS: freeTCPUDPPort(t),
		addUserPath: filepath.Join(cellDir, "victim-user.json"),
	}
	readiness := startTCPEcho(t).(*net.TCPAddr)
	s.bystanderEcho = startRevokeEchoServer(t, certificate, privateKey, false)
	s.victimEcho = s.bystanderEcho
	if cell.flow != "" {
		// Vision copies raw bytes only once the inner traffic is TLS 1.3; a
		// plain-text echo keeps it in its padded TLS layer.
		s.victimEcho = startRevokeEchoServer(t, certificate, privateKey, true)
	}
	realityTarget := ""
	if cell.security == "reality" {
		realityTarget = startRealityCoverServer(t, certificate, privateKey)
	}

	serverPort := freeTCPPort(t)
	serverPath := filepath.Join(cellDir, "server.json")
	writeConfig(t, serverPath, revokeServerConfig(t, cell, serverPort, s.apiPort, certificate, privateKey, realityTarget))
	writeConfig(t, s.addUserPath, revokeAddUserConfig(t, cell, serverPort))
	s.server = startE2EProcess(t, binaries.xray, "run", "-config", serverPath)
	waitTCP(t, s.server, serverPort)

	victimServerPort := serverPort
	if cell.carrier != "direct" {
		s.relay = startCountingRelay(t, serverPort)
		victimServerPort = s.relay.port
	}
	victimBinary, victimArgs, victimConfig := revokeVictimClientConfig(t, binaries, cell, victimServerPort, s.victimSOCKS, certificate)
	victimPath := filepath.Join(cellDir, "victim"+configExtension(cell.peer, false))
	victimArgs = replaceConfigPath(victimArgs, victimPath)
	writeConfig(t, victimPath, victimConfig)
	s.victim = startReadyE2EClient(t, cell.peer, victimBinary, victimArgs, s.victimSOCKS)

	bystanderPath := filepath.Join(cellDir, "bystander.json")
	writeConfig(t, bystanderPath, revokeBystanderClientConfig(t, cell, serverPort, s.bystanderSOCKS, certificate))
	bystander := startReadyE2EClient(t, "xray", binaries.xray, []string{"run", "-config", bystanderPath}, s.bystanderSOCKS)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s server logs:\n%s", s.name, s.server.logs.String())
			t.Logf("%s victim %s client logs:\n%s", s.name, cell.peer, s.victim.logs.String())
			t.Logf("%s bystander xray client logs:\n%s", s.name, bystander.logs.String())
		}
	})

	// An open SOCKS port is not readiness: each client must carry a complete
	// SOCKS-to-server-to-echo round trip.
	waitSOCKSTCPForwarding(t, s.victim, s.victimSOCKS, readiness)
	waitSOCKSTCPForwarding(t, bystander, s.bystanderSOCKS, readiness)
	return s
}

// openVictimFlows opens the victim's long-lived flows and proves what they
// exercise: one carrier on Mux.Cool, direct copy on Vision.
func (s *revokeScenario) openVictimFlows() []*revokeFlow {
	t := s.t
	if s.cell.flow != "" {
		if logs := s.server.logs.String(); revokeVisionDirectIn.MatchString(logs) || revokeVisionDirectOut.MatchString(logs) {
			t.Fatalf("%s: the server switched Vision to direct copy before any TLS flow, so the switch cannot prove the victim's flows use it", s.name)
		}
	}
	var carriersAtReady int64
	if s.relay != nil {
		carriersAtReady = s.relay.accepted.Load()
	}
	flows := make([]*revokeFlow, revokeVictimFlows)
	for i := range flows {
		flows[i] = s.openFlow(s.victimSOCKS, s.victimEcho, fmt.Sprintf("victim-%d", i+1))
	}
	for i, flow := range flows {
		if upstreams := s.victimEcho.upstreams(flow.label); len(upstreams) != 1 {
			t.Fatalf("%s: victim flow %d reached the echo fixture through %d upstream connections, want 1", s.name, i+1, len(upstreams))
		}
	}
	if s.relay != nil {
		carriers := s.relay.accepted.Load()
		t.Logf("%s: the victim client opened %d carrier(s) for its readiness check and %d flows (%d during the flows)", s.name, carriers, revokeVictimFlows, carriers-carriersAtReady)
		if s.cell.carrier == "muxcool" && carriers != 1 {
			t.Fatalf("%s: Mux.Cool spread the readiness check and %d victim flows over %d carriers, want one shared carrier", s.name, revokeVictimFlows, carriers)
		}
	}
	if s.cell.flow != "" {
		revokeWaitLogMatches(t, s.name, s.server, revokeVisionDirectIn, revokeVictimFlows)
		revokeWaitLogMatches(t, s.name, s.server, revokeVisionDirectOut, revokeVictimFlows)
	}
	return flows
}

// openFlow opens a flow that must echo at once.
func (s *revokeScenario) openFlow(socksPort int, fixture *revokeEchoServer, label string) *revokeFlow {
	t := s.t
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	flow, err := revokeDialFlow(socksPort, fixture, label, deadline)
	if err != nil {
		t.Fatalf("%s: open %s flow: %v", s.name, label, err)
	}
	t.Cleanup(flow.close)
	if err := flow.roundTrip(deadline); err != nil {
		t.Fatalf("%s: %s flow did not echo: %v", s.name, label, err)
	}
	return flow
}

// api runs `xray api <command>` against the server and requires its success
// line: the commands print an error and count zero users instead of failing.
func (s *revokeScenario) api(command, want string, arguments ...string) {
	t := s.t
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	arguments = append([]string{"api", command, fmt.Sprintf("--server=127.0.0.1:%d", s.apiPort)}, arguments...)
	output, err := exec.CommandContext(ctx, s.xray, arguments...).CombinedOutput()
	if err != nil || !strings.Contains(string(output), want) {
		t.Fatalf("%s: xray %s did not report %q (exit: %v):\n%s", s.name, strings.Join(arguments, " "), want, err, output)
	}
	t.Logf("%s: xray %s: %s", s.name, strings.Join(arguments, " "), strings.ReplaceAll(strings.TrimSpace(string(output)), "\n", "; "))
}

// assertVictimFlowsEnd requires every victim flow to end on the client side
// (a read returns EOF or a connection error; an expired read deadline proves
// nothing) and at the echo fixture within revokeDeadline of the removal,
// while the bystander keeps echoing.
func (s *revokeScenario) assertVictimFlowsEnd(victims []*revokeFlow, bystander *revokeFlow, removedAt time.Time) {
	t := s.t
	deadline := removedAt.Add(revokeDeadline)
	ends := make([]chan revokeEnd, len(victims))
	for i, flow := range victims {
		ends[i] = make(chan revokeEnd, 1)
		go func() { ends[i] <- flow.awaitEnd(deadline) }()
	}
	if err := bystander.roundTrip(time.Now().Add(revokeDeadline)); err != nil {
		t.Errorf("%s: bystander flow stopped echoing while the victim was being removed: %v", s.name, err)
	}
	for i := range victims {
		end := <-ends[i]
		switch {
		case end.err != nil:
			t.Logf("%s: victim flow %d ended %s after rmu: %v", s.name, i+1, end.at.Sub(removedAt).Round(time.Millisecond), end.err)
		case end.echoes > 0:
			t.Errorf("%s: victim flow %d still echoes %s after rmu (%d fresh lines echoed after rmu, the last %s after it)",
				s.name, i+1, revokeDeadline, end.echoes, end.at.Sub(removedAt).Round(time.Millisecond))
		default:
			t.Errorf("%s: victim flow %d neither ended nor echoed within %s after rmu; only read deadlines expired", s.name, i+1, revokeDeadline)
		}
	}
	for i, flow := range victims {
		upstream := s.victimEcho.upstreams(flow.label)[0]
		select {
		case <-upstream.closed:
		case <-time.After(time.Until(deadline)):
			t.Errorf("%s: the echo fixture still holds victim flow %d's upstream connection open %s after rmu", s.name, i+1, revokeDeadline)
		}
	}
	if err := bystander.roundTrip(time.Now().Add(revokeDeadline)); err != nil {
		t.Errorf("%s: bystander flow stopped echoing after the victim's flows were checked: %v", s.name, err)
	}
	if upstreams := s.bystanderEcho.upstreams(bystander.label); len(upstreams) != 1 || upstreams[0].isClosed() {
		t.Errorf("%s: the bystander's upstream connection did not survive the victim's removal", s.name)
	}
	if t.Failed() {
		t.FailNow()
	}
}

// assertRemovedVictimRejected requires a new flow of the removed victim to
// stay away from the echo fixture. Over REALITY the TLS layer succeeds and
// VLESS then rejects; a cover-site response is not proxy success, so only the
// fixture's accept count decides.
func (s *revokeScenario) assertRemovedVictimRejected(bystander *revokeFlow) {
	t := s.t
	acceptedBefore := s.victimEcho.accepted.Load()
	deadline := time.Now().Add(3 * time.Second)
	flow, err := revokeDialFlow(s.victimSOCKS, s.victimEcho, "victim-removed", deadline)
	if err == nil {
		t.Cleanup(flow.close)
		if err = flow.roundTrip(deadline); err == nil {
			t.Fatalf("%s: a new flow of the removed victim echoed through the server", s.name)
		}
	}
	if accepted := s.victimEcho.accepted.Load() - acceptedBefore; accepted != 0 {
		t.Fatalf("%s: a new flow of the removed victim reached the echo fixture (%d new upstream connection(s)); flow error: %v", s.name, accepted, err)
	}
	t.Logf("%s: the removed victim's new flow did not reach the echo fixture: %v", s.name, err)
	if err := bystander.roundTrip(time.Now().Add(revokeDeadline)); err != nil {
		t.Fatalf("%s: bystander flow stopped echoing after the removed victim was rejected: %v", s.name, err)
	}
}

// assertReaddedVictimEchoes polls, as readiness, for a new victim flow that
// echoes through the same running victim client after `adu`, then requires
// the old flows to stay ended and the bystander to keep echoing.
func (s *revokeScenario) assertReaddedVictimEchoes(victims []*revokeFlow, bystander *revokeFlow) {
	t := s.t
	deadline := time.Now().Add(10 * time.Second)
	for attempt := 1; ; attempt++ {
		attemptDeadline := revokeEarlier(deadline, time.Now().Add(2*time.Second))
		flow, err := revokeDialFlow(s.victimSOCKS, s.victimEcho, fmt.Sprintf("victim-readded-%d", attempt), attemptDeadline)
		if err == nil {
			t.Cleanup(flow.close)
			if err = flow.roundTrip(attemptDeadline); err == nil {
				t.Logf("%s: the re-added victim echoed through a new flow on attempt %d", s.name, attempt)
				break
			}
			flow.close()
		}
		if serverExited(s.victim) {
			t.Fatalf("%s: the victim client exited before the re-added victim echoed: %v", s.name, err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("%s: the re-added victim did not echo through a new flow of the same client within 10s: %v", s.name, err)
		}
		time.Sleep(25 * time.Millisecond) // interval between readiness attempts
	}
	for i, flow := range victims {
		if _, err := flow.readLine(time.Now().Add(250 * time.Millisecond)); err == nil || revokeTimeout(err) {
			t.Errorf("%s: victim flow %d no longer reads as ended after the victim was re-added: %v", s.name, i+1, err)
		}
		if upstreams := s.victimEcho.upstreams(flow.label); len(upstreams) != 1 || !upstreams[0].isClosed() {
			t.Errorf("%s: victim flow %d's upstream reopened or stayed open after the victim was re-added (%d upstream connection(s))", s.name, i+1, len(upstreams))
		}
	}
	if err := bystander.roundTrip(time.Now().Add(revokeDeadline)); err != nil {
		t.Errorf("%s: bystander flow stopped echoing after the victim was re-added: %v", s.name, err)
	}
}

func revokeServerConfig(t *testing.T, cell revokeCell, serverPort, apiPort int, certificate, privateKey, realityTarget string) []byte {
	t.Helper()
	logLevel := "warning"
	if cell.flow != "" {
		logLevel = "debug" // records revokeVisionDirectIn and revokeVisionDirectOut
	}
	inbound := revokeInbound(cell, serverPort, revokeUser(cell, revokeVictimEmail), revokeUser(cell, revokeBystanderEmail))
	inbound["streamSettings"] = xrayVLESSTCPStreamSettings(true, cell.security, certificate, privateKey, realityTarget)
	config := map[string]any{
		"log": map[string]any{"loglevel": logLevel},
		"api": map[string]any{
			"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", apiPort), "services": []string{"HandlerService"},
		},
		"inbounds": []any{inbound},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	}
	return revokeMarshal(t, config)
}

// revokeAddUserConfig is the `xray api adu` input that re-adds the victim
// with the same email and credentials.
func revokeAddUserConfig(t *testing.T, cell revokeCell, serverPort int) []byte {
	t.Helper()
	return revokeMarshal(t, map[string]any{"inbounds": []any{revokeInbound(cell, serverPort, revokeUser(cell, revokeVictimEmail))}})
}

func revokeInbound(cell revokeCell, serverPort int, users ...map[string]any) map[string]any {
	clients := make([]any, len(users))
	for i, user := range users {
		clients[i] = user
	}
	settings := map[string]any{"clients": clients}
	if cell.protocol == "vless" {
		settings["decryption"] = "none"
	}
	return map[string]any{
		"tag": revokeInboundTag, "listen": "127.0.0.1", "port": serverPort,
		"protocol": cell.protocol, "settings": settings,
	}
}

func revokeUser(cell revokeCell, email string) map[string]any {
	victim := email == revokeVictimEmail
	if cell.protocol == "trojan" {
		password := revokeBystanderPassword
		if victim {
			password = testPassword
		}
		return map[string]any{"password": password, "email": email}
	}
	id := revokeBystanderUUID
	if victim {
		id = testUUID
	}
	return map[string]any{"id": id, "email": email, "flow": cell.flow}
}

func revokeVictimClientConfig(t *testing.T, binaries e2eBinaries, cell revokeCell, serverPort, socksPort int, certificate string) (string, []string, []byte) {
	t.Helper()
	switch {
	case cell.carrier == "muxcool":
		// Concurrency 8 lets the readiness check and every flow share one carrier.
		return binaries.xray, []string{"run", "-config", "client.json"}, xrayMuxCoolTCPClientConfig(t, serverPort, socksPort, cell.security, certificate, 0)
	case cell.protocol == "vless":
		binary, arguments, config := vlessTCPClientConfig(t, binaries, cell.peer, serverPort, socksPort, cell.security, cell.flow, certificate)
		if cell.carrier == "smux" {
			config = revokeWithSMUX(t, cell.peer, config)
		}
		return binary, arguments, config
	default:
		// peerClientConfig builds Trojan over TLS with SMUX for every peer.
		binary, arguments, config := peerClientConfig(t, binaries, cell.peer, "trojan", serverPort, socksPort, "smux", false, certificate)
		if cell.carrier == "direct" {
			config = revokeWithoutSMUX(t, cell.peer, config)
		}
		return binary, arguments, config
	}
}

// revokeBystanderClientConfig is an Xray client with the bystander's
// credentials and the cell's protocol, security, and flow on a direct carrier.
func revokeBystanderClientConfig(t *testing.T, cell revokeCell, serverPort, socksPort int, certificate string) []byte {
	t.Helper()
	if cell.protocol == "vless" {
		return revokeEditOutbound(t, xrayVLESSTCPConfig(t, false, serverPort, socksPort, cell.security, cell.flow, certificate, "", ""), func(outbound map[string]any) {
			vnext := outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
			vnext["users"].([]any)[0].(map[string]any)["id"] = revokeBystanderUUID
		})
	}
	return revokeEditOutbound(t, xrayConfig(t, false, "trojan", serverPort, socksPort, "smux", false, certificate, ""), func(outbound map[string]any) {
		revokeDeleteKey(t, outbound, "smux")
		outbound["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["password"] = revokeBystanderPassword
	})
}

func revokeWithSMUX(t *testing.T, peer string, config []byte) []byte {
	t.Helper()
	switch peer {
	case "xray":
		return revokeEditOutbound(t, config, func(outbound map[string]any) {
			outbound["smux"] = map[string]any{"enabled": true, "protocol": "smux", "maxConnections": 1, "padding": false}
		})
	case "sing-box":
		return revokeEditOutbound(t, config, func(outbound map[string]any) {
			outbound["multiplex"] = map[string]any{"enabled": true, "protocol": "smux", "max_connections": 1, "padding": false}
		})
	default:
		return revokeReplaceOnce(t, config, "proxy-groups:\n",
			"    smux:\n      enabled: true\n      protocol: smux\n      max-connections: 1\n      padding: false\nproxy-groups:\n")
	}
}

func revokeWithoutSMUX(t *testing.T, peer string, config []byte) []byte {
	t.Helper()
	switch peer {
	case "xray":
		return revokeEditOutbound(t, config, func(outbound map[string]any) { revokeDeleteKey(t, outbound, "smux") })
	case "sing-box":
		return revokeEditOutbound(t, config, func(outbound map[string]any) { revokeDeleteKey(t, outbound, "multiplex") })
	default:
		return revokeReplaceOnce(t, config, "    smux:\n      enabled: true\n", "    smux:\n      enabled: false\n")
	}
}

// revokeEditOutbound applies edit to the first outbound of a JSON client
// configuration.
func revokeEditOutbound(t *testing.T, encoded []byte, edit func(outbound map[string]any)) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	edit(config["outbounds"].([]any)[0].(map[string]any))
	return revokeMarshal(t, config)
}

func revokeDeleteKey(t *testing.T, object map[string]any, key string) {
	t.Helper()
	if _, found := object[key]; !found {
		t.Fatalf("client configuration has no %q to remove: %v", key, object)
	}
	delete(object, key)
}

func revokeReplaceOnce(t *testing.T, config []byte, old, replacement string) []byte {
	t.Helper()
	if count := bytes.Count(config, []byte(old)); count != 1 {
		t.Fatalf("client configuration holds %q %d times, want once:\n%s", old, count, config)
	}
	return bytes.Replace(config, []byte(old), []byte(replacement), 1)
}

func revokeMarshal(t *testing.T, config map[string]any) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// revokeEchoServer echoes newline-terminated lines. It names each accepted
// upstream connection by the label of its first line ("<label>#<seq>") and
// records when that connection ends.
type revokeEchoServer struct {
	address  *net.TCPAddr
	tls      bool
	listener net.Listener
	accepted atomic.Int64
	workers  sync.WaitGroup
	mu       sync.Mutex
	stopped  bool
	open     map[net.Conn]struct{}
	labels   map[string][]*revokeUpstream
}

type revokeUpstream struct {
	closed chan struct{}
}

func (u *revokeUpstream) isClosed() bool {
	select {
	case <-u.closed:
		return true
	default:
		return false
	}
}

// startRevokeEchoServer listens on loopback; with useTLS it accepts TLS 1.3
// only.
func startRevokeEchoServer(t *testing.T, certificate, privateKey string, useTLS bool) *revokeEchoServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &revokeEchoServer{
		address: listener.Addr().(*net.TCPAddr), tls: useTLS,
		open: make(map[net.Conn]struct{}), labels: make(map[string][]*revokeUpstream),
	}
	if useTLS {
		pair, err := cryptotls.LoadX509KeyPair(certificate, privateKey)
		if err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		listener = cryptotls.NewListener(listener, &cryptotls.Config{
			Certificates: []cryptotls.Certificate{pair},
			MinVersion:   cryptotls.VersionTLS13,
		})
	}
	server.listener = listener
	server.workers.Add(1)
	go server.accept()
	t.Cleanup(server.close)
	return server
}

func (s *revokeEchoServer) accept() {
	defer s.workers.Done()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			_ = connection.Close()
			continue
		}
		s.open[connection] = struct{}{}
		s.workers.Add(1)
		s.mu.Unlock()
		go s.serve(connection)
	}
}

func (s *revokeEchoServer) serve(connection net.Conn) {
	defer s.workers.Done()
	var upstream *revokeUpstream
	defer func() {
		_ = connection.Close()
		s.mu.Lock()
		delete(s.open, connection)
		s.mu.Unlock()
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
			upstream = &revokeUpstream{closed: make(chan struct{})}
			s.mu.Lock()
			s.labels[label] = append(s.labels[label], upstream)
			s.mu.Unlock()
		}
		if _, err := io.WriteString(connection, line); err != nil {
			return
		}
	}
}

func (s *revokeEchoServer) upstreams(label string) []*revokeUpstream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*revokeUpstream(nil), s.labels[label]...)
}

func (s *revokeEchoServer) close() {
	_ = s.listener.Close()
	s.mu.Lock()
	s.stopped = true
	for connection := range s.open {
		_ = connection.Close()
	}
	s.mu.Unlock()
	s.workers.Wait()
}

// revokeFlow is one SOCKS connection to an echo fixture, carrying TLS inside
// when the fixture requires it. Every line it writes is unique.
type revokeFlow struct {
	label   string
	conn    net.Conn // the SOCKS connection
	stream  net.Conn // conn, or the TLS session inside it
	pending []byte
	seq     int
}

func revokeDialFlow(socksPort int, fixture *revokeEchoServer, label string, deadline time.Time) (*revokeFlow, error) {
	connection, err := dialSOCKSTCPAttempt(socksPort, fixture.address.IP.String(), fixture.address.Port)
	if err != nil {
		return nil, fmt.Errorf("SOCKS connect: %w", err)
	}
	flow := &revokeFlow{label: label, conn: connection, stream: connection}
	if fixture.tls {
		_ = connection.SetDeadline(deadline)
		session := cryptotls.Client(connection, &cryptotls.Config{
			InsecureSkipVerify: true, // generated loopback certificate
			MinVersion:         cryptotls.VersionTLS13,
			ServerName:         "localhost",
		})
		if err := session.Handshake(); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("inner TLS handshake: %w", err)
		}
		flow.stream = session
	}
	_ = connection.SetDeadline(time.Time{})
	return flow, nil
}

func (f *revokeFlow) close() { _ = f.conn.Close() }

func (f *revokeFlow) nextLine() string {
	f.seq++
	return fmt.Sprintf("%s#%d\n", f.label, f.seq)
}

func (f *revokeFlow) write(line string, deadline time.Time) error {
	_ = f.conn.SetWriteDeadline(deadline)
	_, err := io.WriteString(f.stream, line)
	return err
}

// readLine returns the next echoed line. Bytes read before a deadline expires
// stay pending for the next call.
func (f *revokeFlow) readLine(deadline time.Time) (string, error) {
	_ = f.conn.SetReadDeadline(deadline)
	buffer := make([]byte, 1024)
	for {
		if end := bytes.IndexByte(f.pending, '\n'); end >= 0 {
			line := string(f.pending[:end+1])
			f.pending = f.pending[end+1:]
			return line, nil
		}
		n, err := f.stream.Read(buffer)
		f.pending = append(f.pending, buffer[:n]...)
		if err != nil && bytes.IndexByte(f.pending, '\n') < 0 {
			return "", err
		}
	}
}

func (f *revokeFlow) roundTrip(deadline time.Time) error {
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

// revokeEnd is what a victim flow showed after its user was removed: the
// read error that ended it, or the fresh lines it still echoed.
type revokeEnd struct {
	err    error
	echoes int
	at     time.Time // when it ended, or when it last echoed
}

// awaitEnd keeps writing fresh lines until a read ends the flow or deadline
// passes. Between writes it reads without writing, so an end shows up even
// when the flow would still accept writes.
func (f *revokeFlow) awaitEnd(deadline time.Time) revokeEnd {
	var result revokeEnd
	observe := func(wait time.Duration) bool {
		_, err := f.readLine(revokeEarlier(deadline, time.Now().Add(wait)))
		switch {
		case err == nil:
			result.echoes++
			result.at = time.Now()
		case !revokeTimeout(err):
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

// revokeWaitLogMatches waits until process has logged pattern at least count
// times.
func revokeWaitLogMatches(t *testing.T, name string, process *e2eProcess, pattern *regexp.Regexp, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		matches := len(pattern.FindAllStringIndex(process.logs.String(), -1))
		if matches >= count {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("%s: the server logged %q %d times, want at least %d: Vision did not switch every victim flow to direct copy", name, pattern, matches, count)
		}
		time.Sleep(10 * time.Millisecond) // poll interval for the asynchronous log
	}
}

func revokeTimeout(err error) bool {
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

func revokeEarlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
