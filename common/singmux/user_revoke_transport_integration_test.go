//go:build integration

package singmux_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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

// Removing a user through HandlerService (xray api rmu) must end the live
// connections the user already has on the server, whatever the transport,
// leave every other user alone, and let the same credentials in again once
// xray api adu re-adds them (upstream XTLS/Xray-core#5844).

const (
	revokeTransportInboundTag        = "revoke-in"
	revokeTransportVictimEmail       = "victim@revoke.test"
	revokeTransportBystanderEmail    = "bystander@revoke.test"
	revokeTransportVictimUUID        = "6a4f2c1e-8d3b-4f7a-9c2e-1b5d7e9f0a11"
	revokeTransportBystanderUUID     = "6a4f2c1e-8d3b-4f7a-9c2e-1b5d7e9f0a22"
	revokeTransportVictimPassword    = "revoke-transport-victim-password"
	revokeTransportBystanderPassword = "revoke-transport-bystander-password"

	// revokeTransportEndWindow is how long a removed user's flow may outlive
	// a successful rmu.
	revokeTransportEndWindow = 5 * time.Second
	// revokeTransportStalledWindow is how long a flow whose reader stalled
	// may outlive rmu: Xray's websocket Close first waits up to 5s to queue
	// its close frame behind the blocked write.
	revokeTransportStalledWindow = 2 * revokeTransportEndWindow
	// revokeTransportTagSize is the fixed-size name every flow sends first,
	// so the echo fixture can tell its upstream connections apart.
	revokeTransportTagSize = 32
	// revokeTransportPushPrefix makes the echo fixture push data instead of
	// echoing it.
	revokeTransportPushPrefix = "push-"
	revokeTransportLogTail    = 32 << 10
)

type revokeTransportCell struct {
	name    string
	carrier string // "vless" or "trojan"
	network string // "ws", "httpupgrade", "grpc", "xhttp", or "raw"
	mode    string // XHTTP mode
	stalled bool   // the victim stops reading before rmu
	// knownStallLimit marks a stalled cell whose flow cannot end before the
	// reader resumes: XHTTP's httpServerConn.Close waits for the mutex its
	// Write holds while HTTP/2 flow control blocks that Write.
	knownStallLimit bool
	mux             bool // the victim client carries UDP over Mux.Cool XUDP
}

// TestRemovedUserConnectionsTransportProcess removes a user while it holds
// live TCP flows through an Xray client on each transport. Each flow must end
// within revokeTransportEndWindow on both sides of the server, the other
// user's flow keeps echoing, a new flow of the removed user never reaches the
// destination, and adu lets the same running client in again. The
// stalled-reader cells remove the user while the server's downlink write to it
// is blocked because the local reader stopped reading.
func TestRemovedUserConnectionsTransportProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level user removal across transports")
	}
	workDir := t.TempDir()
	xray := revokeTransportBuildXray(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	readyEcho := startTCPEcho(t).(*net.TCPAddr)

	cells := []revokeTransportCell{
		{name: "websocket", carrier: "vless", network: "ws"},
		{name: "httpupgrade", carrier: "vless", network: "httpupgrade"},
		{name: "grpc", carrier: "vless", network: "grpc"},
		{name: "xhttp-packet-up", carrier: "vless", network: "xhttp", mode: "packet-up"},
		{name: "xhttp-stream-up", carrier: "vless", network: "xhttp", mode: "stream-up"},
		{name: "xhttp-stream-one", carrier: "vless", network: "xhttp", mode: "stream-one"},
		{name: "trojan-websocket", carrier: "trojan", network: "ws"},
		{name: "websocket-stalled-reader", carrier: "vless", network: "ws", stalled: true},
		{name: "xhttp-stream-one-stalled-reader", carrier: "vless", network: "xhttp", mode: "stream-one", stalled: true, knownStallLimit: true},
	}
	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			topology := startRevokeTransportTopology(t, workDir, xray, cell, certificate, privateKey, false)
			waitSOCKSTCPForwarding(t, topology.victim, topology.victimSOCKS, readyEcho)
			waitSOCKSTCPForwarding(t, topology.bystander, topology.bystanderSOCKS, readyEcho)
			echo := startRevokeTransportEcho(t)
			if cell.stalled {
				runRevokeTransportStalledCell(t, cell, topology, echo)
				return
			}
			runRevokeTransportCell(t, cell, topology, echo)
		})
	}
}

func runRevokeTransportCell(t *testing.T, cell revokeTransportCell, topology *revokeTransportTopology, echo *revokeTransportEcho) {
	victims := make([]*revokeTransportFlow, 3)
	for i := range victims {
		victims[i] = openRevokeTransportFlow(t, cell.name, topology.victimSOCKS, echo, fmt.Sprintf("victim-%d", i+1))
	}
	bystander := openRevokeTransportFlow(t, cell.name, topology.bystanderSOCKS, echo, "bystander")
	for _, flow := range append(append([]*revokeTransportFlow(nil), victims...), bystander) {
		if err := flow.echo(); err != nil {
			t.Fatalf("%s: %s flow does not echo before rmu: %v", cell.name, flow.name, err)
		}
	}

	issued := revokeTransportRemoveVictim(t, cell.name, topology)
	deadline := time.Now().Add(revokeTransportEndWindow)
	ends := awaitRevokeTransportFlowEnds(t, cell.name, victims, bystander, deadline)
	// Judge the upstreams before anything writes into a victim flow: a write
	// can itself end a flow the server only marked closed.
	for i, victim := range victims {
		if !echo.awaitClosed(victim.name, deadline) {
			t.Errorf("%s: echo fixture still holds victim flow %d's upstream %v after rmu", cell.name, i+1, revokeTransportEndWindow)
			continue
		}
		t.Logf("%s: echo fixture saw victim flow %d's upstream end %v after rmu was issued", cell.name, i+1, echo.upstream(victim.name).closedAt().Sub(issued).Round(time.Millisecond))
	}
	for i, end := range ends {
		if end.unexpected != 0 {
			t.Errorf("%s: victim flow %d received %d bytes nobody sent after rmu", cell.name, i+1, end.unexpected)
		}
		if end.ended {
			t.Logf("%s: victim flow %d ended %v after rmu was issued: %v", cell.name, i+1, end.at.Sub(issued).Round(time.Millisecond), end.err)
			continue
		}
		if err := victims[i].echo(); err == nil {
			t.Errorf("%s: victim flow %d still echoes %v after rmu", cell.name, i+1, revokeTransportEndWindow)
		} else {
			t.Errorf("%s: victim flow %d did not end within %v after rmu; a later echo attempt failed: %v", cell.name, i+1, revokeTransportEndWindow, err)
		}
	}
	if echo.isClosed(bystander.name) {
		t.Errorf("%s: the bystander's upstream closed when the victim was removed", cell.name)
	}
	if err := bystander.echo(); err != nil {
		t.Errorf("%s: bystander flow stopped echoing after rmu: %v", cell.name, err)
	}

	assertRevokeTransportFlowRejected(t, cell.name, topology.victimSOCKS, echo, "victim-after-rmu")

	revokeTransportAddVictim(t, cell, topology)
	readded := awaitRevokeTransportFlow(t, cell.name, topology.victim, topology.victimSOCKS, echo, "victim-readded")
	if err := readded.echo(); err != nil {
		t.Errorf("%s: re-added victim flow stopped echoing: %v", cell.name, err)
	}
	for i, end := range ends {
		if !end.ended {
			continue // already reported
		}
		// The client may still accept a write into the dead flow; nothing
		// may come back from it.
		_, _ = victims[i].conn.Write([]byte("after-adu"))
		if again := victims[i].awaitEnd(time.Now().Add(time.Second)); !again.ended || again.unexpected != 0 {
			t.Errorf("%s: victim flow %d came back after adu (ended %t, %d bytes)", cell.name, i+1, again.ended, again.unexpected)
		}
	}
	if err := bystander.echo(); err != nil {
		t.Errorf("%s: bystander flow stopped echoing after adu: %v", cell.name, err)
	}
	if echo.isClosed(bystander.name) {
		t.Errorf("%s: the bystander's upstream closed during the test", cell.name)
	}
}

// runRevokeTransportStalledCell removes the victim while its local reader has
// stopped reading and the echo fixture keeps pushing, so the server's
// downlink write to the victim is blocked. Unless the cell has a known stall
// limit, the server must end the upstream within revokeTransportStalledWindow
// while the reader stays stalled; in every cell, once the reader resumes the
// flow must end promptly and the fixture cannot keep pushing.
func runRevokeTransportStalledCell(t *testing.T, cell revokeTransportCell, topology *revokeTransportTopology, echo *revokeTransportEcho) {
	const name = revokeTransportPushPrefix + "victim"
	victim := openRevokeTransportPushFlow(t, cell.name, topology.victimSOCKS, echo, name)
	bystander := openRevokeTransportFlow(t, cell.name, topology.bystanderSOCKS, echo, "bystander")
	if err := bystander.echo(); err != nil {
		t.Fatalf("%s: bystander flow does not echo before rmu: %v", cell.name, err)
	}
	upstream := echo.upstream(name)
	stalledAt := waitRevokeTransportStall(t, cell.name, upstream)
	if err := bystander.echo(); err != nil {
		t.Fatalf("%s: bystander flow stopped echoing while the victim's downlink stalled: %v", cell.name, err)
	}

	issued := revokeTransportRemoveVictim(t, cell.name, topology)
	closedWhileStalled := awaitRevokeTransportUpstreamClosed(t, cell.name, upstream, bystander, time.Now().Add(revokeTransportStalledWindow))
	pushedWhileStalled := upstream.pushed.Load() - stalledAt
	switch {
	case closedWhileStalled:
		t.Logf("%s: OBSERVED the server ended the victim upstream %v after rmu was issued while the reader was still stalled (fixture pushed %d bytes after rmu)",
			cell.name, upstream.closedAt().Sub(issued).Round(time.Millisecond), pushedWhileStalled)
	case cell.knownStallLimit:
		t.Logf("%s: OBSERVED the victim upstream still open %v after rmu while the reader was stalled (fixture pushed %d bytes after rmu); known limitation, judged after the reader resumes",
			cell.name, revokeTransportStalledWindow, pushedWhileStalled)
	default:
		t.Errorf("%s: victim upstream still open %v after rmu while the reader was stalled (fixture pushed %d bytes after rmu)",
			cell.name, revokeTransportStalledWindow, pushedWhileStalled)
	}

	resumed := time.Now()
	delivered, end := victim.drain(resumed.Add(revokeTransportEndWindow))
	pushedAfterRemoval := upstream.pushed.Load() - stalledAt
	if !end.ended {
		t.Errorf("%s: victim flow still delivers payload %v after the reader resumed (%d bytes since resume, fixture pushed %d bytes after rmu)",
			cell.name, revokeTransportEndWindow, delivered, pushedAfterRemoval)
	} else {
		t.Logf("%s: OBSERVED victim flow ended %v after the reader resumed (%v after rmu was issued) with %d bytes delivered since resume: %v",
			cell.name, end.at.Sub(resumed).Round(time.Millisecond), end.at.Sub(issued).Round(time.Millisecond), delivered, end.err)
	}
	if !upstream.awaitClosed(resumed.Add(revokeTransportEndWindow)) {
		t.Errorf("%s: echo fixture still holds the victim upstream %v after the reader resumed", cell.name, revokeTransportEndWindow)
	}
	// Everything the server forwards after rmu has to fit in the buffers the
	// stall left behind: a server that kept forwarding lets the fixture push
	// for as long as the reader reads.
	pushedAfterRemoval = upstream.pushed.Load() - stalledAt
	if pushedAfterRemoval > stalledAt {
		t.Errorf("%s: the fixture pushed %d victim bytes after rmu, more than the %d bytes that stalled the downlink",
			cell.name, pushedAfterRemoval, stalledAt)
	}
	t.Logf("%s: OBSERVED downlink stalled after %d pushed bytes; %d bytes pushed after rmu", cell.name, stalledAt, pushedAfterRemoval)
	if err := bystander.echo(); err != nil {
		t.Errorf("%s: bystander flow stopped echoing after rmu: %v", cell.name, err)
	}
	if echo.isClosed(bystander.name) {
		t.Errorf("%s: the bystander's upstream closed when the victim was removed", cell.name)
	}
}

// TestRemovedUserUDPProcess removes a user while its Xray client relays SOCKS
// UDP through it: VLESS XUDP over TLS, VLESS with Mux.Cool XUDP, and Trojan
// UDP over TLS. A relay between each client and the server shows the server
// closing the victim's carrier; afterwards no fresh victim nonce reaches the
// UDP echo fixture, the bystander keeps round-tripping, and after adu the same
// client process round-trips again.
func TestRemovedUserUDPProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level user removal over UDP")
	}
	workDir := t.TempDir()
	xray := revokeTransportBuildXray(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)

	cells := []revokeTransportCell{
		{name: "vless-tls-xudp", carrier: "vless", network: "raw"},
		{name: "vless-tls-muxcool-xudp", carrier: "vless", network: "raw", mux: true},
		{name: "trojan-tls", carrier: "trojan", network: "raw"},
	}
	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			topology := startRevokeTransportTopology(t, workDir, xray, cell, certificate, privateKey, true)
			echo := startRevokeTransportUDPEcho(t)
			victim := openRevokeTransportUDPAssociation(t, cell.name, topology.victimSOCKS, echo.address)
			bystander := openRevokeTransportUDPAssociation(t, cell.name, topology.bystanderSOCKS, echo.address)
			victim.awaitRoundTrip(t, cell.name, topology.victim, "victim-ready")
			bystander.awaitRoundTrip(t, cell.name, topology.bystander, "bystander-ready")
			for range 3 {
				for _, association := range []*revokeTransportUDPAssociation{victim, bystander} {
					if _, err := association.roundTrip("fresh", 5*time.Second); err != nil {
						t.Fatalf("%s: fresh nonce before rmu: %v", cell.name, err)
					}
				}
			}
			carriers := topology.victimRelay.openCarriers()
			if len(carriers) == 0 {
				t.Fatalf("%s: the victim client has no open carrier before rmu", cell.name)
			}
			bystanderCarriers := topology.bystanderRelay.openCarriers()

			issued := revokeTransportRemoveVictim(t, cell.name, topology)
			if awaitRevokeTransportCarriersClosed(t, cell.name, carriers, bystander, time.Now().Add(revokeTransportEndWindow)) {
				t.Logf("%s: the server closed %d victim carrier(s) by %v after rmu was issued", cell.name, len(carriers), time.Since(issued).Round(time.Millisecond))
				// A fresh association needs a new carrier whatever the
				// client does with the old one.
				probe := openRevokeTransportUDPAssociation(t, cell.name, topology.victimSOCKS, echo.address)
				assertRevokeTransportUDPWindow(t, cell.name, topology.victimRelay, []*revokeTransportUDPAssociation{victim, probe}, bystander, echo)
			} else {
				t.Errorf("%s: %d victim carrier(s) still open %v after rmu", cell.name, countRevokeTransportOpen(carriers), revokeTransportEndWindow)
				if nonce, err := victim.roundTrip("victim-after-rmu", 2*time.Second); err == nil {
					t.Errorf("%s: fresh victim nonce %q still round-trips %v after rmu", cell.name, nonce, revokeTransportEndWindow)
				}
			}
			for _, carrier := range bystanderCarriers {
				if carrier.closedByServer() {
					t.Errorf("%s: the server closed a bystander carrier when the victim was removed", cell.name)
				}
			}
			if _, err := bystander.roundTrip("bystander-after-rmu", 5*time.Second); err != nil {
				t.Errorf("%s: bystander UDP stopped round-tripping after rmu: %v", cell.name, err)
			}

			revokeTransportAddVictim(t, cell, topology)
			// A new association through the same client process: an Xray
			// client does not tear down Mux.Cool sessions whose carrier
			// failed, so the old association may stay attached to it.
			readded := openRevokeTransportUDPAssociation(t, cell.name, topology.victimSOCKS, echo.address)
			readded.awaitRoundTrip(t, cell.name, topology.victim, "victim-readded")
			if _, err := bystander.roundTrip("bystander-after-adu", 5*time.Second); err != nil {
				t.Errorf("%s: bystander UDP stopped round-tripping after adu: %v", cell.name, err)
			}
		})
	}
}

// assertRevokeTransportUDPWindow sends fresh victim nonces through every
// victim association for a bounded window after the server closed the
// victim's carrier, waits until the server has closed every carrier the victim
// client opened in the window, and then requires that no nonce reached the
// echo fixture or came back.
func assertRevokeTransportUDPWindow(t *testing.T, cellName string, relay *revokeTransportRelay, victims []*revokeTransportUDPAssociation, bystander *revokeTransportUDPAssociation, echo *revokeTransportUDPEcho) {
	t.Helper()
	acceptedBefore := relay.acceptedCount()
	var sent []string
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	windowEnd := time.Now().Add(2 * time.Second)
	bystanderFailed := false
	for now := time.Now(); now.Before(windowEnd); now = <-ticker.C {
		for _, victim := range victims {
			nonce := victim.nextNonce("victim-revoked")
			if err := victim.send(nonce); err != nil {
				t.Fatalf("%s: send victim nonce: %v", cellName, err)
			}
			sent = append(sent, nonce)
		}
		if bystanderFailed {
			continue
		}
		if _, err := bystander.roundTrip("bystander-window", 2*time.Second); err != nil {
			bystanderFailed = true
			t.Errorf("%s: bystander UDP stopped round-tripping after the victim's carrier closed: %v", cellName, err)
		}
	}
	attempts := relay.carriersSince(acceptedBefore)
	if len(attempts) == 0 {
		t.Errorf("%s: the victim client opened no carrier during the window, so the window proves nothing", cellName)
	}
	deadline := time.Now().Add(revokeTransportEndWindow)
	for _, carrier := range attempts {
		if !carrier.awaitServerClosed(deadline) {
			t.Errorf("%s: the server kept a new victim carrier open after rmu", cellName)
		}
	}
	for _, victim := range victims {
		if payload, err := victim.receive(time.Now().Add(200 * time.Millisecond)); err == nil {
			t.Errorf("%s: the victim received %q after the server closed its carrier", cellName, payload)
		}
	}
	for _, nonce := range sent {
		if echo.seen(nonce) {
			t.Errorf("%s: fresh victim nonce %q reached the echo fixture after the server closed the victim's carrier", cellName, nonce)
		}
	}
	t.Logf("%s: %d victim nonces sent after the carrier closed; the victim client opened %d carrier(s) meanwhile",
		cellName, len(sent), len(attempts))
}

func revokeTransportBuildXray(t *testing.T, workDir string) string {
	t.Helper()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
}

type revokeTransportTopology struct {
	xray                        string
	dir                         string
	serverPort, apiPort         int
	server, victim, bystander   *e2eProcess
	victimSOCKS, bystanderSOCKS int
	victimRelay, bystanderRelay *revokeTransportRelay
}

// startRevokeTransportTopology starts one Xray server with the API and one
// Xray client per user. relayed puts a revokeTransportRelay in front of the
// server for each client.
func startRevokeTransportTopology(t *testing.T, workDir, xray string, cell revokeTransportCell, certificate, privateKey string, relayed bool) *revokeTransportTopology {
	t.Helper()
	dir := filepath.Join(workDir, strings.NewReplacer("/", "-", "=", "-").Replace(t.Name()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	topology := &revokeTransportTopology{xray: xray, dir: dir, serverPort: freeTCPPort(t), apiPort: freeTCPPort(t)}
	serverPath := filepath.Join(dir, "server.json")
	writeConfig(t, serverPath, revokeTransportServerConfig(t, cell, topology.serverPort, topology.apiPort, certificate, privateKey))
	topology.server = startE2EProcess(t, xray, "run", "-config", serverPath)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s server logs (tail):\n%s", cell.name, revokeTransportTail(topology.server.logs.String()))
		}
	})
	waitTCP(t, topology.server, topology.serverPort)
	waitTCP(t, topology.server, topology.apiPort)

	victimPort, bystanderPort := topology.serverPort, topology.serverPort
	if relayed {
		topology.victimRelay = startRevokeTransportRelay(t, topology.serverPort)
		topology.bystanderRelay = startRevokeTransportRelay(t, topology.serverPort)
		victimPort, bystanderPort = topology.victimRelay.port, topology.bystanderRelay.port
	}
	topology.victim, topology.victimSOCKS = startRevokeTransportClient(t, cell, xray, dir, "victim", victimPort, certificate)
	topology.bystander, topology.bystanderSOCKS = startRevokeTransportClient(t, cell, xray, dir, "bystander", bystanderPort, certificate)
	return topology
}

func startRevokeTransportClient(t *testing.T, cell revokeTransportCell, xray, dir, role string, serverPort int, certificate string) (*e2eProcess, int) {
	t.Helper()
	socksPort := freeTCPUDPPort(t)
	path := filepath.Join(dir, role+".json")
	writeConfig(t, path, revokeTransportClientConfig(t, cell, role == "victim", serverPort, socksPort, certificate))
	client := startReadyE2EClient(t, "xray", xray, []string{"run", "-config", path}, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s %s client logs (tail):\n%s", cell.name, role, revokeTransportTail(client.logs.String()))
		}
	})
	return client, socksPort
}

func revokeTransportServerConfig(t *testing.T, cell revokeTransportCell, serverPort, apiPort int, certificate, privateKey string) []byte {
	t.Helper()
	settings := map[string]any{"clients": []any{
		revokeTransportAccount(cell.carrier, true),
		revokeTransportAccount(cell.carrier, false),
	}}
	if cell.carrier == "vless" {
		settings["decryption"] = "none"
	}
	return revokeTransportJSON(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"api": map[string]any{
			"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", apiPort), "services": []string{"HandlerService"},
		},
		"inbounds": []any{map[string]any{
			"tag": revokeTransportInboundTag, "listen": "127.0.0.1", "port": serverPort, "protocol": cell.carrier,
			"settings":       settings,
			"streamSettings": revokeTransportStreamSettings(true, cell, certificate, privateKey),
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	})
}

func revokeTransportClientConfig(t *testing.T, cell revokeTransportCell, victim bool, serverPort, socksPort int, certificate string) []byte {
	t.Helper()
	var settings map[string]any
	if cell.carrier == "vless" {
		id := revokeTransportBystanderUUID
		if victim {
			id = revokeTransportVictimUUID
		}
		settings = map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": serverPort,
			"users": []any{map[string]any{"id": id, "encryption": "none"}},
		}}}
	} else {
		password := revokeTransportBystanderPassword
		if victim {
			password = revokeTransportVictimPassword
		}
		settings = map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": serverPort, "password": password,
		}}}
	}
	outbound := map[string]any{
		"protocol":       cell.carrier,
		"settings":       settings,
		"streamSettings": revokeTransportStreamSettings(false, cell, certificate, ""),
	}
	if cell.mux {
		outbound["mux"] = map[string]any{"enabled": true, "concurrency": 8, "xudpConcurrency": 8}
	}
	return revokeTransportJSON(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		}},
		"outbounds": []any{outbound},
	})
}

// revokeTransportAccount is the server-side (and adu) account of a user.
func revokeTransportAccount(carrier string, victim bool) map[string]any {
	email, id, password := revokeTransportBystanderEmail, revokeTransportBystanderUUID, revokeTransportBystanderPassword
	if victim {
		email, id, password = revokeTransportVictimEmail, revokeTransportVictimUUID, revokeTransportVictimPassword
	}
	if carrier == "vless" {
		return map[string]any{"id": id, "email": email}
	}
	return map[string]any{"password": password, "email": email}
}

func revokeTransportStreamSettings(server bool, cell revokeTransportCell, certificate, privateKey string) map[string]any {
	stream := xrayTLSSettings(server, certificate, privateKey)
	switch cell.network {
	case "ws":
		stream["network"] = "ws"
		stream["wsSettings"] = map[string]any{"path": "/revoke-ws"}
	case "httpupgrade":
		stream["network"] = "httpupgrade"
		stream["httpupgradeSettings"] = map[string]any{"path": "/revoke-upgrade"}
	case "grpc":
		stream["network"] = "grpc"
		stream["grpcSettings"] = map[string]any{"serviceName": "revoke", "multiMode": false}
	case "xhttp":
		stream["tlsSettings"].(map[string]any)["alpn"] = []string{"h2"}
		stream["network"] = "xhttp"
		stream["xhttpSettings"] = map[string]any{"path": "/revoke-xhttp", "mode": cell.mode}
	case "raw":
	default:
		panic("unknown revoke transport " + cell.network)
	}
	return stream
}

func revokeTransportJSON(t *testing.T, config map[string]any) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func revokeTransportTail(logs string) string {
	if len(logs) <= revokeTransportLogTail {
		return logs
	}
	return "...\n" + logs[len(logs)-revokeTransportLogTail:]
}

// revokeTransportAPI runs one xray api command against the server and
// requires its summary line: rmu and adu exit 0 even when they change
// nothing.
func revokeTransportAPI(t *testing.T, cellName string, topology *revokeTransportTopology, want, command string, arguments ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	arguments = append([]string{"api", command, fmt.Sprintf("--server=127.0.0.1:%d", topology.apiPort)}, arguments...)
	output, err := exec.CommandContext(ctx, topology.xray, arguments...).CombinedOutput()
	if err != nil || !strings.Contains(string(output), want) {
		t.Fatalf("%s: xray %s: %v, want %q in:\n%s", cellName, strings.Join(arguments, " "), err, want, output)
	}
}

// revokeTransportRemoveVictim removes the victim and returns when it issued
// rmu; the windows start once rmu has returned.
func revokeTransportRemoveVictim(t *testing.T, cellName string, topology *revokeTransportTopology) time.Time {
	t.Helper()
	issued := time.Now()
	revokeTransportAPI(t, cellName, topology, "Removed 1 user(s) in total.", "rmu", "-tag="+revokeTransportInboundTag, revokeTransportVictimEmail)
	return issued
}

func revokeTransportAddVictim(t *testing.T, cell revokeTransportCell, topology *revokeTransportTopology) {
	t.Helper()
	settings := map[string]any{"clients": []any{revokeTransportAccount(cell.carrier, true)}}
	if cell.carrier == "vless" {
		settings["decryption"] = "none"
	}
	path := filepath.Join(topology.dir, "victim-adu.json")
	writeConfig(t, path, revokeTransportJSON(t, map[string]any{"inbounds": []any{map[string]any{
		"tag": revokeTransportInboundTag, "listen": "127.0.0.1", "port": topology.serverPort,
		"protocol": cell.carrier, "settings": settings,
	}}}))
	revokeTransportAPI(t, cell.name, topology, "Added 1 user(s) in total.", "adu", path)
}

func revokeTransportRandomHex() string {
	var random [6]byte
	_, _ = rand.Read(random[:])
	return hex.EncodeToString(random[:])
}

func revokeTransportTag(name string) []byte {
	if len(name) >= revokeTransportTagSize {
		panic("revoke flow name too long: " + name)
	}
	return []byte(fmt.Sprintf("%-*s\n", revokeTransportTagSize-1, name))
}

// revokeTransportEcho is the TCP destination of every flow. Each upstream
// connection starts with a revokeTransportTag naming its flow; the fixture
// records when that upstream ends. A flow named with revokeTransportPushPrefix
// gets a continuous stream instead of an echo.
type revokeTransportEcho struct {
	address *net.TCPAddr
	mu      sync.Mutex
	flows   map[string]*revokeTransportUpstream
}

type revokeTransportUpstream struct {
	closed   chan struct{}
	closedNs atomic.Int64
	pushed   atomic.Int64
}

func (u *revokeTransportUpstream) closedAt() time.Time { return time.Unix(0, u.closedNs.Load()) }

// awaitClosed reports whether the upstream ended by deadline.
func (u *revokeTransportUpstream) awaitClosed(deadline time.Time) bool {
	select {
	case <-u.closed:
		return true
	default:
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-u.closed:
		return true
	case <-timer.C:
		return false
	}
}

func startRevokeTransportEcho(t *testing.T) *revokeTransportEcho {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	echo := &revokeTransportEcho{address: listener.Addr().(*net.TCPAddr), flows: map[string]*revokeTransportUpstream{}}
	var connections sync.WaitGroup
	var openMu sync.Mutex
	open := map[*net.TCPConn]struct{}{}
	accepting := make(chan struct{})
	go func() {
		defer close(accepting)
		for {
			connection, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			openMu.Lock()
			open[connection] = struct{}{}
			openMu.Unlock()
			connections.Go(func() {
				echo.serve(connection)
				openMu.Lock()
				delete(open, connection)
				openMu.Unlock()
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepting
		openMu.Lock()
		for connection := range open {
			_ = connection.Close()
		}
		openMu.Unlock()
		connections.Wait()
	})
	return echo
}

func (e *revokeTransportEcho) serve(connection *net.TCPConn) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	tag := make([]byte, revokeTransportTagSize)
	if _, err := io.ReadFull(connection, tag); err != nil {
		return
	}
	_ = connection.SetReadDeadline(time.Time{})
	name := strings.TrimSpace(string(tag))
	upstream := &revokeTransportUpstream{closed: make(chan struct{})}
	e.mu.Lock()
	e.flows[name] = upstream
	e.mu.Unlock()
	defer func() {
		upstream.closedNs.Store(time.Now().UnixNano())
		close(upstream.closed)
	}()
	if strings.HasPrefix(name, revokeTransportPushPrefix) {
		revokeTransportPush(connection, upstream)
		return
	}
	if _, err := connection.Write(tag); err != nil {
		return
	}
	_, _ = io.Copy(connection, connection)
}

// revokeTransportPush writes until the server ends the upstream: a read that
// returns means the server closed it, a failed write that it reset it.
func revokeTransportPush(connection *net.TCPConn, upstream *revokeTransportUpstream) {
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		_, _ = io.Copy(io.Discard, connection)
		_ = connection.Close()
	}()
	chunk := bytes.Repeat([]byte("revoke-push-pay"), 32<<10/15)
	for {
		n, err := connection.Write(chunk)
		upstream.pushed.Add(int64(n))
		if err != nil {
			break
		}
	}
	_ = connection.Close()
	<-readerDone
}

func (e *revokeTransportEcho) upstream(name string) *revokeTransportUpstream {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.flows[name]
}

func (e *revokeTransportEcho) awaitClosed(name string, deadline time.Time) bool {
	upstream := e.upstream(name)
	return upstream == nil || upstream.awaitClosed(deadline)
}

func (e *revokeTransportEcho) isClosed(name string) bool {
	upstream := e.upstream(name)
	if upstream == nil {
		return false
	}
	select {
	case <-upstream.closed:
		return true
	default:
		return false
	}
}

type revokeTransportFlow struct {
	name     string
	conn     net.Conn
	sequence int
}

// revokeTransportFlowEnd is what a flow's reader saw: ended is false when the
// read deadline expired with the flow still open, which proves nothing.
type revokeTransportFlowEnd struct {
	ended      bool
	err        error
	at         time.Time
	unexpected int
}

func dialRevokeTransportFlow(socksPort int, echo *revokeTransportEcho, name string) (*revokeTransportFlow, error) {
	connection, err := dialSOCKSTCPAttempt(socksPort, "127.0.0.1", echo.address.Port)
	if err != nil {
		return nil, fmt.Errorf("open SOCKS flow %s: %w", name, err)
	}
	flow := &revokeTransportFlow{name: name, conn: connection}
	tag := revokeTransportTag(name)
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write(tag); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("flow %s: write tag: %w", name, err)
	}
	if !strings.HasPrefix(name, revokeTransportPushPrefix) {
		reply := make([]byte, len(tag))
		if _, err := io.ReadFull(connection, reply); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("flow %s: read tag echo: %w", name, err)
		}
		if !bytes.Equal(reply, tag) {
			_ = connection.Close()
			return nil, fmt.Errorf("flow %s: tag echo %q", name, reply)
		}
	}
	_ = connection.SetDeadline(time.Time{})
	return flow, nil
}

func openRevokeTransportFlow(t *testing.T, cellName string, socksPort int, echo *revokeTransportEcho, name string) *revokeTransportFlow {
	t.Helper()
	flow, err := dialRevokeTransportFlow(socksPort, echo, name)
	if err != nil {
		t.Fatalf("%s: %v", cellName, err)
	}
	t.Cleanup(func() { _ = flow.conn.Close() })
	return flow
}

// openRevokeTransportPushFlow opens a flow the fixture pushes data into and
// reads the first bytes of it to prove the path; the caller then stops
// reading.
func openRevokeTransportPushFlow(t *testing.T, cellName string, socksPort int, echo *revokeTransportEcho, name string) *revokeTransportFlow {
	t.Helper()
	flow := openRevokeTransportFlow(t, cellName, socksPort, echo, name)
	_ = flow.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(flow.conn, make([]byte, 1024)); err != nil {
		t.Fatalf("%s: read pushed data on %s: %v", cellName, name, err)
	}
	_ = flow.conn.SetReadDeadline(time.Time{})
	if echo.upstream(name) == nil {
		t.Fatalf("%s: echo fixture has no upstream for %s", cellName, name)
	}
	return flow
}

// echo sends a fresh unique payload and requires it back.
func (f *revokeTransportFlow) echo() error {
	f.sequence++
	payload := []byte(fmt.Sprintf("%s-%d-%s", f.name, f.sequence, revokeTransportRandomHex()))
	_ = f.conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer f.conn.SetDeadline(time.Time{})
	if _, err := f.conn.Write(payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(f.conn, response); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if !bytes.Equal(response, payload) {
		return fmt.Errorf("echo %q, want %q", response, payload)
	}
	return nil
}

// awaitEnd reads until the flow ends or deadline expires; nothing was sent,
// so every byte that arrives is counted as unexpected.
func (f *revokeTransportFlow) awaitEnd(deadline time.Time) revokeTransportFlowEnd {
	_ = f.conn.SetReadDeadline(deadline)
	defer f.conn.SetReadDeadline(time.Time{})
	buffer := make([]byte, 4096)
	var end revokeTransportFlowEnd
	for {
		n, err := f.conn.Read(buffer)
		end.unexpected += n
		if err == nil {
			continue
		}
		end.err = err
		var networkErr net.Error
		if errors.As(err, &networkErr) && networkErr.Timeout() {
			return end
		}
		end.ended, end.at = true, time.Now()
		return end
	}
}

// drain reads and discards until the flow ends or deadline expires.
func (f *revokeTransportFlow) drain(deadline time.Time) (int64, revokeTransportFlowEnd) {
	_ = f.conn.SetReadDeadline(deadline)
	defer f.conn.SetReadDeadline(time.Time{})
	buffer := make([]byte, 64<<10)
	var delivered int64
	var end revokeTransportFlowEnd
	for {
		n, err := f.conn.Read(buffer)
		delivered += int64(n)
		if err == nil {
			continue
		}
		end.err = err
		var networkErr net.Error
		if errors.As(err, &networkErr) && networkErr.Timeout() {
			return delivered, end
		}
		end.ended, end.at = true, time.Now()
		return delivered, end
	}
}

// awaitRevokeTransportFlowEnds waits for each victim flow to end by deadline
// while the bystander keeps echoing fresh payloads.
func awaitRevokeTransportFlowEnds(t *testing.T, cellName string, victims []*revokeTransportFlow, bystander *revokeTransportFlow, deadline time.Time) []revokeTransportFlowEnd {
	t.Helper()
	type indexedEnd struct {
		index int
		end   revokeTransportFlowEnd
	}
	results := make(chan indexedEnd, len(victims))
	for i, victim := range victims {
		go func() { results <- indexedEnd{i, victim.awaitEnd(deadline)} }()
	}
	ends := make([]revokeTransportFlowEnd, len(victims))
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	bystanderFailed := false
	for pending := len(victims); pending > 0; {
		select {
		case result := <-results:
			ends[result.index] = result.end
			pending--
		case <-ticker.C:
			if bystanderFailed {
				continue
			}
			if err := bystander.echo(); err != nil {
				bystanderFailed = true
				t.Errorf("%s: bystander flow stopped echoing while the victim was removed: %v", cellName, err)
			}
		}
	}
	return ends
}

// awaitRevokeTransportUpstreamClosed reports whether upstream ends by
// deadline while the bystander keeps echoing.
func awaitRevokeTransportUpstreamClosed(t *testing.T, cellName string, upstream *revokeTransportUpstream, bystander *revokeTransportFlow, deadline time.Time) bool {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	bystanderFailed := false
	for {
		select {
		case <-upstream.closed:
			return true
		case <-timer.C:
			return upstream.awaitClosed(time.Now())
		case <-ticker.C:
			if bystanderFailed {
				continue
			}
			if err := bystander.echo(); err != nil {
				bystanderFailed = true
				t.Errorf("%s: bystander flow stopped echoing while the victim was removed: %v", cellName, err)
			}
		}
	}
}

// assertRevokeTransportFlowRejected opens a new flow through the victim's
// client and requires that it ends without ever reaching the echo fixture.
func assertRevokeTransportFlowRejected(t *testing.T, cellName string, socksPort int, echo *revokeTransportEcho, name string) {
	t.Helper()
	connection, err := dialSOCKSTCPAttempt(socksPort, "127.0.0.1", echo.address.Port)
	if err != nil {
		t.Fatalf("%s: open SOCKS flow %s: %v", cellName, name, err)
	}
	defer connection.Close()
	flow := &revokeTransportFlow{name: name, conn: connection}
	_, _ = connection.Write(revokeTransportTag(name))
	end := flow.awaitEnd(time.Now().Add(10 * time.Second))
	switch {
	case end.unexpected != 0:
		t.Fatalf("%s: a new victim flow got %d bytes back after rmu", cellName, end.unexpected)
	case !end.ended:
		t.Fatalf("%s: a new victim flow neither failed nor echoed within 10s after rmu", cellName)
	}
	if echo.upstream(name) != nil {
		t.Fatalf("%s: a new victim flow reached the echo fixture after rmu", cellName)
	}
}

// awaitRevokeTransportFlow polls until a new flow named after base echoes
// through the client, as readiness after adu.
func awaitRevokeTransportFlow(t *testing.T, cellName string, client *e2eProcess, socksPort int, echo *revokeTransportEcho, base string) *revokeTransportFlow {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for attempt := 1; ; attempt++ {
		flow, err := dialRevokeTransportFlow(socksPort, echo, fmt.Sprintf("%s-%d", base, attempt))
		if err == nil {
			if err = flow.echo(); err == nil {
				t.Cleanup(func() { _ = flow.conn.Close() })
				return flow
			}
			_ = flow.conn.Close()
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("%s: the same victim client has no working flow 10s after adu: %v", cellName, lastErr)
		}
		select {
		case processErr := <-client.done:
			t.Fatalf("%s: victim client exited after adu: %v", cellName, processErr)
		case <-ticker.C:
		}
	}
}

// waitRevokeTransportStall waits until the fixture has pushed a meaningful
// amount and then could not push anything for a second: every buffer between
// it and the stalled reader, the server's downlink included, is full.
func waitRevokeTransportStall(t *testing.T, cellName string, upstream *revokeTransportUpstream) int64 {
	t.Helper()
	const (
		quiet = time.Second
		floor = 256 << 10
	)
	deadline := time.Now().Add(30 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	last, lastChange := upstream.pushed.Load(), time.Now()
	for {
		select {
		case <-upstream.closed:
			t.Fatalf("%s: the victim upstream closed before its downlink stalled (%d bytes pushed)", cellName, upstream.pushed.Load())
		case now := <-ticker.C:
			if pushed := upstream.pushed.Load(); pushed != last {
				last, lastChange = pushed, now
				continue
			}
			if last >= floor && now.Sub(lastChange) >= quiet {
				return last
			}
			if now.After(deadline) {
				t.Fatalf("%s: the victim downlink did not stall within 30s (%d bytes pushed)", cellName, last)
			}
		}
	}
}

// revokeTransportRelay forwards loopback TCP to the server and records, for
// each connection, when the server side ended it.
type revokeTransportRelay struct {
	port     int
	mu       sync.Mutex
	carriers []*revokeTransportCarrier
}

type revokeTransportCarrier struct {
	serverClosed chan struct{}
}

func (c *revokeTransportCarrier) closedByServer() bool {
	select {
	case <-c.serverClosed:
		return true
	default:
		return false
	}
}

func (c *revokeTransportCarrier) awaitServerClosed(deadline time.Time) bool {
	if c.closedByServer() {
		return true
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-c.serverClosed:
		return true
	case <-timer.C:
		return false
	}
}

func startRevokeTransportRelay(t *testing.T, serverPort int) *revokeTransportRelay {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relay := &revokeTransportRelay{port: listener.Addr().(*net.TCPAddr).Port}
	var connections sync.WaitGroup
	var openMu sync.Mutex
	open := map[net.Conn]struct{}{}
	track := func(connection net.Conn) {
		openMu.Lock()
		open[connection] = struct{}{}
		openMu.Unlock()
	}
	accepting := make(chan struct{})
	go func() {
		defer close(accepting)
		for {
			client, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			server, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			carrier := &revokeTransportCarrier{serverClosed: make(chan struct{})}
			relay.mu.Lock()
			relay.carriers = append(relay.carriers, carrier)
			relay.mu.Unlock()
			track(client)
			track(server)
			connections.Go(func() {
				_, _ = io.Copy(server, client)
				_ = server.(*net.TCPConn).CloseWrite()
			})
			connections.Go(func() {
				_, _ = io.Copy(client, server)
				close(carrier.serverClosed)
				_ = client.Close()
				_ = server.Close()
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepting
		openMu.Lock()
		for connection := range open {
			_ = connection.Close()
		}
		openMu.Unlock()
		connections.Wait()
	})
	return relay
}

func (r *revokeTransportRelay) acceptedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.carriers)
}

func (r *revokeTransportRelay) carriersSince(index int) []*revokeTransportCarrier {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*revokeTransportCarrier(nil), r.carriers[index:]...)
}

func (r *revokeTransportRelay) openCarriers() []*revokeTransportCarrier {
	var open []*revokeTransportCarrier
	for _, carrier := range r.carriersSince(0) {
		if !carrier.closedByServer() {
			open = append(open, carrier)
		}
	}
	return open
}

func countRevokeTransportOpen(carriers []*revokeTransportCarrier) int {
	open := 0
	for _, carrier := range carriers {
		if !carrier.closedByServer() {
			open++
		}
	}
	return open
}

// awaitRevokeTransportCarriersClosed reports whether the server closed every
// carrier by deadline while the bystander keeps round-tripping.
func awaitRevokeTransportCarriersClosed(t *testing.T, cellName string, carriers []*revokeTransportCarrier, bystander *revokeTransportUDPAssociation, deadline time.Time) bool {
	t.Helper()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	bystanderFailed := false
	for {
		if countRevokeTransportOpen(carriers) == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		<-ticker.C
		if bystanderFailed {
			continue
		}
		if _, err := bystander.roundTrip("bystander-rmu", 2*time.Second); err != nil {
			bystanderFailed = true
			t.Errorf("%s: bystander UDP stopped round-tripping while the victim was removed: %v", cellName, err)
		}
	}
}

// revokeTransportUDPEcho echoes datagrams and records every payload it
// received.
type revokeTransportUDPEcho struct {
	address  *net.UDPAddr
	mu       sync.Mutex
	received map[string]int
}

func startRevokeTransportUDPEcho(t *testing.T) *revokeTransportUDPEcho {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	echo := &revokeTransportUDPEcho{address: connection.LocalAddr().(*net.UDPAddr), received: map[string]int{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		payload := make([]byte, 65535)
		for {
			n, address, err := connection.ReadFromUDP(payload)
			if err != nil {
				return
			}
			echo.mu.Lock()
			echo.received[string(payload[:n])]++
			echo.mu.Unlock()
			_, _ = connection.WriteToUDP(payload[:n], address)
		}
	}()
	t.Cleanup(func() {
		_ = connection.Close()
		<-done
	})
	return echo
}

func (e *revokeTransportUDPEcho) seen(nonce string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.received[nonce] != 0
}

// revokeTransportUDPAssociation is one SOCKS UDP association kept open for a
// whole cell, so every nonce goes through the same client association.
type revokeTransportUDPAssociation struct {
	control     net.Conn
	socket      *net.UDPConn
	relay       *net.UDPAddr
	destination *net.UDPAddr
	sequence    int
}

func openRevokeTransportUDPAssociation(t *testing.T, cellName string, socksPort int, destination *net.UDPAddr) *revokeTransportUDPAssociation {
	t.Helper()
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		t.Fatalf("%s: dial SOCKS: %v", cellName, err)
	}
	t.Cleanup(func() { _ = control.Close() })
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socksGreeting(control); err != nil {
		t.Fatalf("%s: SOCKS greeting: %v", cellName, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("%s: SOCKS UDP associate: %v", cellName, err)
	}
	relay, err := readSOCKSReplyAddress(control)
	if err != nil {
		t.Fatalf("%s: SOCKS UDP associate reply: %v", cellName, err)
	}
	_ = control.SetDeadline(time.Time{})
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return &revokeTransportUDPAssociation{control: control, socket: socket, relay: relay, destination: destination}
}

func (a *revokeTransportUDPAssociation) nextNonce(prefix string) string {
	a.sequence++
	return fmt.Sprintf("%s-%d-%s", prefix, a.sequence, revokeTransportRandomHex())
}

func (a *revokeTransportUDPAssociation) send(nonce string) error {
	packet := append([]byte{0, 0, 0, 1}, a.destination.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(a.destination.Port))
	packet = append(packet, nonce...)
	_, err := a.socket.WriteToUDP(packet, a.relay)
	return err
}

// receive returns the payload of the next datagram that arrives by deadline.
func (a *revokeTransportUDPAssociation) receive(deadline time.Time) (string, error) {
	_ = a.socket.SetReadDeadline(deadline)
	buffer := make([]byte, 65535)
	n, _, err := a.socket.ReadFromUDP(buffer)
	if err != nil {
		return "", err
	}
	offset, err := socksAddressLength(buffer[:n], 3)
	if err != nil {
		return "", err
	}
	return string(buffer[offset:n]), nil
}

// roundTrip sends a fresh nonce and waits for its echo, skipping late echoes
// of earlier nonces.
func (a *revokeTransportUDPAssociation) roundTrip(prefix string, timeout time.Duration) (string, error) {
	nonce := a.nextNonce(prefix)
	if err := a.send(nonce); err != nil {
		return nonce, fmt.Errorf("send %q: %w", nonce, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		payload, err := a.receive(deadline)
		if err != nil {
			return nonce, fmt.Errorf("await %q: %w", nonce, err)
		}
		if payload == nonce {
			return nonce, nil
		}
	}
}

// awaitRoundTrip polls fresh nonces until one round-trips, as readiness.
func (a *revokeTransportUDPAssociation) awaitRoundTrip(t *testing.T, cellName string, client *e2eProcess, prefix string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, lastErr = a.roundTrip(prefix, 300*time.Millisecond); lastErr == nil {
			return
		}
		select {
		case processErr := <-client.done:
			t.Fatalf("%s: client exited before %s round-tripped: %v", cellName, prefix, processErr)
		default:
		}
	}
	t.Fatalf("%s: no %s nonce round-tripped within 10s: %v", cellName, prefix, lastErr)
}
