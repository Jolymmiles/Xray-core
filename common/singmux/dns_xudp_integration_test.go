//go:build integration

package singmux_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const dnsXUDPUpstreamAnswer = "192.0.2.53"

// TestDNSOutboundXUDPProcessMatrix sends DNS queries over VLESS UDP from each
// client to one Xray server whose DNS outbound has sendThrough and passes
// every query to the upstream. Xray (UDP from its SOCKS inbound) and Mihomo
// send XUDP with a Global ID, which the server serves as a timeout-only
// session; before the DNS outbound kept that session's context, its
// sendThrough dial panicked and the query was never answered. sing-box sends
// XUDP without a Global ID, which the server serves as a plain mux stream.
func TestDNSOutboundXUDPProcessMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level DNS outbound XUDP matrix")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	upstream := startDNSXUDPUpstream(t)

	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		t.Run(peer, func(t *testing.T) {
			runDNSXUDPScenario(t, workDir, binaries, peer, upstream)
		})
	}
}

func runDNSXUDPScenario(t *testing.T, workDir string, binaries e2eBinaries, peer string, upstream *net.UDPAddr) {
	t.Helper()
	serverPort := freeTCPPort(t)
	// Mihomo's SOCKS inbound binds the port for both TCP and UDP.
	socksPort := freeTCPUDPPort(t)
	scenarioDir := filepath.Join(workDir, strings.NewReplacer("/", "-").Replace(t.Name()))
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}

	serverPath := filepath.Join(scenarioDir, "server.json")
	writeConfig(t, serverPath, xrayDNSXUDPServerConfig(t, serverPort))
	server := startE2EProcess(t, binaries.xray, "run", "-config", serverPath)
	waitTCP(t, server, serverPort)

	clientBinary, clientArgs, clientConfig := dnsXUDPClientConfig(t, binaries, peer, serverPort, socksPort)
	clientPath := filepath.Join(scenarioDir, "client"+configExtension(peer, peer == "xray"))
	clientArgs = replaceConfigPath(clientArgs, clientPath)
	writeConfig(t, clientPath, clientConfig)
	client := startReadyE2EClient(t, peer, clientBinary, clientArgs, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
			t.Logf("client logs:\n%s", client.logs.String())
		}
	})

	// Each association is one UDP flow; the second one checks that a new
	// flow works after the first one was used.
	id := uint16(1)
	for association := range 2 {
		exchanges := make([]string, 0, 2)
		for query := range 2 {
			exchanges = append(exchanges, fmt.Sprintf("q%d-%d.example.com", association, query))
		}
		if err := exchangeSOCKSDNS(socksPort, upstream, &id, exchanges...); err != nil {
			t.Fatalf("association %d: %v", association, err)
		}
	}
}

func startDNSXUDPUpstream(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := pc.LocalAddr().(*net.UDPAddr)
	// VLESS clients carry UDP to these ports without XUDP.
	if address.Port == 53 || address.Port == 443 {
		pc.Close()
		t.Fatalf("upstream DNS port %d is not carried as XUDP", address.Port)
	}
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ans := new(dns.Msg)
			ans.SetReply(r)
			for _, q := range r.Question {
				if q.Qtype == dns.TypeA {
					rr, err := dns.NewRR(q.Name + " IN A " + dnsXUDPUpstreamAnswer)
					if err != nil {
						panic(err)
					}
					ans.Answer = append(ans.Answer, rr)
				}
			}
			_ = w.WriteMsg(ans)
		}),
		NotifyStartedFunc: func() { close(started) },
	}
	served := make(chan struct{})
	var serveErr error
	go func() {
		serveErr = server.ActivateAndServe()
		close(served)
	}()
	// Join the serve goroutine on every path. Closing the socket releases it
	// even when the server never started.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := server.ShutdownContext(ctx)
		_ = pc.Close()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("upstream DNS server did not stop within 5s")
			return
		}
		select {
		case <-started:
			if shutdownErr != nil {
				t.Errorf("shut down upstream DNS server: %v", shutdownErr)
			}
			if serveErr != nil {
				t.Errorf("upstream DNS server: %v", serveErr)
			}
		default:
		}
	})
	select {
	case <-started:
	case <-served:
		t.Fatalf("upstream DNS server stopped before serving: %v", serveErr)
	case <-time.After(10 * time.Second):
		t.Fatal("upstream DNS server did not start within 10s")
	}
	return address
}

// exchangeSOCKSDNS opens one SOCKS UDP association and sends each A query
// through it in turn, checking that the upstream answered.
func exchangeSOCKSDNS(socksPort int, upstream *net.UDPAddr, id *uint16, names ...string) error {
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	if err := socksGreeting(control); err != nil {
		return err
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	relay, err := readSOCKSReplyAddress(control)
	if err != nil {
		return err
	}
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer udp.Close()

	header := append([]byte{0, 0, 0, 1}, upstream.IP.To4()...)
	header = binary.BigEndian.AppendUint16(header, uint16(upstream.Port))
	response := make([]byte, 65535)
	for _, name := range names {
		*id++
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(name), dns.TypeA)
		query.Id = *id
		packed, err := query.Pack()
		if err != nil {
			return err
		}
		if _, err := udp.WriteToUDP(append(append([]byte(nil), header...), packed...), relay); err != nil {
			return fmt.Errorf("send query for %s: %w", name, err)
		}
		_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := udp.ReadFromUDP(response)
		if err != nil {
			return fmt.Errorf("no answer for %s: %w", name, err)
		}
		offset, err := socksAddressLength(response[:n], 3)
		if err != nil {
			return err
		}
		answer := new(dns.Msg)
		if err := answer.Unpack(response[offset:n]); err != nil {
			return fmt.Errorf("unpack answer for %s: %w", name, err)
		}
		if answer.Id != *id || len(answer.Answer) != 1 {
			return fmt.Errorf("answer for %s (ID %d) = %v", name, *id, answer)
		}
		if a, ok := answer.Answer[0].(*dns.A); !ok || a.A.String() != dnsXUDPUpstreamAnswer {
			return fmt.Errorf("answer for %s is %v, want the upstream's %s", name, answer.Answer[0], dnsXUDPUpstreamAnswer)
		}
	}
	return nil
}

func xrayDNSXUDPServerConfig(t *testing.T, serverPort int) []byte {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": serverPort, "protocol": "vless",
			"settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": testUUID}}},
		}},
		"outbounds": []any{map[string]any{
			"protocol":    "dns",
			"sendThrough": "127.0.0.1",
			"settings":    map[string]any{"rules": []any{map[string]any{"action": "direct"}}},
		}},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func dnsXUDPClientConfig(t *testing.T, binaries e2eBinaries, peer string, serverPort, socksPort int) (string, []string, []byte) {
	t.Helper()
	var config any
	switch peer {
	case "xray":
		config = map[string]any{
			"log": map[string]any{"loglevel": "debug"},
			"inbounds": []any{map[string]any{
				"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
			}},
			"outbounds": []any{map[string]any{
				"protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": "127.0.0.1", "port": serverPort,
					"users": []any{map[string]any{"id": testUUID, "encryption": "none"}},
				}}},
			}},
		}
	case "sing-box":
		config = map[string]any{
			"log":      map[string]any{"level": "debug"},
			"inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
			"outbounds": []any{map[string]any{
				"type": "vless", "server": "127.0.0.1", "server_port": serverPort, "uuid": testUUID,
				"packet_encoding": "xudp",
			}},
		}
	case "mihomo":
		yaml := fmt.Sprintf("socks-port: %d\nallow-lan: false\nmode: global\nlog-level: debug\nproxies:\n  - name: vless-e2e\n    type: vless\n    server: 127.0.0.1\n    port: %d\n    uuid: %s\n    network: tcp\n    tls: false\n    udp: true\n    packet-encoding: xudp\nproxy-groups:\n  - name: GLOBAL\n    type: select\n    proxies:\n      - vless-e2e\n", socksPort, serverPort, testUUID)
		return binaries.mihomo, []string{"-d", ".", "-f", "client.yaml"}, []byte(yaml)
	default:
		t.Fatalf("unsupported DNS XUDP peer %q", peer)
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if peer == "xray" {
		return binaries.xray, []string{"run", "-config", "client.json"}, encoded
	}
	return binaries.singBox, []string{"run", "-c", "client.json"}, encoded
}
