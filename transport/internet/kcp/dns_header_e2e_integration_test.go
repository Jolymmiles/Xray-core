//go:build integration

package kcp_test

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The mKCP "dns" header prefixes every packet, in both directions, with a
// query for the configured domain. A relay between an Xray client and an
// Xray server checks that each datagram it carries starts with a
// well-formed A/IN question for that domain while TCP and UDP traffic flow
// end to end. A domain that would pack a malformed question fails
// `xray run -test`.
func TestMKCPDNSHeaderProcessE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level mKCP dns header end-to-end test")
	}

	workDir := t.TempDir()
	xray := buildMKCPE2EBinary(t, workDir)

	t.Run("malformed-domain", func(t *testing.T) {
		config := mkcpServerConfig(freeMKCPUDPPort(t), nil)
		setMKCPDNSHeader(config, "inbounds", "t.example.")
		path := filepath.Join(t.TempDir(), "server.json")
		writeMKCPConfig(t, path, config)
		output, err := exec.Command(xray, "run", "-test", "-config", path).CombinedOutput()
		if err == nil {
			t.Fatalf("xray run -test accepted the dns header domain t.example.:\n%s", output)
		}
		if want := `invalid domain "t.example.": trailing dot; write "t.example"`; !bytes.Contains(output, []byte(want)) {
			t.Fatalf("xray run -test output does not contain %q:\n%s", want, output)
		}
	})

	t.Run("traffic", func(t *testing.T) {
		const domain = "t.example"
		tcpEcho := startMKCPTCPEcho(t)
		udpEcho := startMKCPUDPEcho(t)
		serverPort := freeMKCPUDPPort(t)
		socksPort := freeMKCPTCPPort(t)
		relay := startMKCPDNSHeaderRelay(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}, domain+".")

		scenarioDir := filepath.Join(workDir, "dns-header")
		serverConfig := filepath.Join(scenarioDir, "server.json")
		clientConfig := filepath.Join(scenarioDir, "client.json")
		serverSettings := mkcpServerConfig(serverPort, nil)
		setMKCPDNSHeader(serverSettings, "inbounds", domain)
		clientSettings := mkcpClientConfig(relay.port(), socksPort, nil)
		setMKCPDNSHeader(clientSettings, "outbounds", domain)
		if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeMKCPConfig(t, serverConfig, serverSettings)
		writeMKCPConfig(t, clientConfig, clientSettings)

		server := startMKCPE2EProcess(t, xray, "run", "-config", serverConfig)
		client := startMKCPE2EProcess(t, xray, "run", "-config", clientConfig)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("mKCP server logs:\n%s", server.logs.String())
				t.Logf("mKCP client logs:\n%s", client.logs.String())
			}
		})

		waitMKCPForwarding(t, server, client, socksPort, tcpEcho)

		payload := bytes.Repeat([]byte("xray-mkcp-dns-header-tcp-"), 12*1024)
		if err := runMKCPSOCKSTCP(socksPort, tcpEcho, payload, 20*time.Second); err != nil {
			t.Fatalf("tcp: %v", err)
		}
		payload = bytes.Repeat([]byte("xray-mkcp-dns-header-udp-"), 192)
		if err := runMKCPSOCKSUDP(socksPort, udpEcho, payload); err != nil {
			t.Fatalf("udp: %v", err)
		}

		relay.verify(t)
	})
}

// A datagram the relay cannot forward is reported as a problem, so a failed
// traffic check names the send error rather than only a SOCKS timeout.
func TestMKCPDNSHeaderRelayReportsSendErrors(t *testing.T) {
	// Linux rejects a send to port 0 with EINVAL.
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	relay := startMKCPDNSHeaderRelay(t, server, "t.example.")
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relay.port()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	select {
	case <-relay.problemc:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not report the datagram it failed to forward to port 0")
	}
	problems := relay.takeProblems()
	if len(problems) != 1 || !strings.Contains(problems[0], "invalid argument") {
		t.Fatalf("relay problems = %q, want one send error", problems)
	}
}

func setMKCPDNSHeader(config map[string]any, direction, domain string) {
	endpoint := config[direction].([]any)[0].(map[string]any)
	endpoint["streamSettings"].(map[string]any)["finalmask"] = map[string]any{
		"udp": []any{map[string]any{
			"type":     "mkcp-legacy",
			"settings": map[string]any{"header": "dns", "value": domain},
		}},
	}
}

// mkcpDNSHeaderRelay forwards datagrams between mKCP clients and one server,
// one upstream socket per client address, and inspects the DNS question at
// the start of each datagram.
type mkcpDNSHeaderRelay struct {
	listener *net.UDPConn
	server   *net.UDPAddr
	name     string
	problemc chan struct{} // gets a token, without blocking, for each problem

	mu        sync.Mutex
	closed    bool
	upstreams map[string]*net.UDPConn
	toServer  int
	toClient  int
	problems  []string
	dropped   int
	wg        sync.WaitGroup
}

func startMKCPDNSHeaderRelay(t *testing.T, server *net.UDPAddr, name string) *mkcpDNSHeaderRelay {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relay := &mkcpDNSHeaderRelay{
		listener:  listener,
		server:    server,
		name:      name,
		problemc:  make(chan struct{}, 1),
		upstreams: make(map[string]*net.UDPConn),
	}
	relay.wg.Add(1)
	go relay.serveClients()
	t.Cleanup(func() {
		relay.mu.Lock()
		relay.closed = true
		_ = relay.listener.Close()
		for _, upstream := range relay.upstreams {
			_ = upstream.Close()
		}
		relay.mu.Unlock()
		relay.wg.Wait()
		// Problems that verify did not take, as when the traffic check stops
		// early, are likely the cause of the failure.
		for _, problem := range relay.takeProblems() {
			t.Error(problem)
		}
	})
	return relay
}

func (r *mkcpDNSHeaderRelay) port() int {
	return r.listener.LocalAddr().(*net.UDPAddr).Port
}

func (r *mkcpDNSHeaderRelay) serveClients() {
	defer r.wg.Done()
	buffer := make([]byte, 65535)
	for {
		n, client, err := r.listener.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		r.inspect("client -> server", buffer[:n])
		upstream := r.upstream(client)
		if upstream == nil {
			continue
		}
		if _, err := upstream.WriteToUDP(buffer[:n], r.server); err != nil {
			r.fail("forward a datagram from %s to %s: %v", client, r.server, err)
		}
	}
}

func (r *mkcpDNSHeaderRelay) upstream(client *net.UDPAddr) *net.UDPConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if upstream := r.upstreams[client.String()]; upstream != nil {
		return upstream
	}
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		r.addProblemLocked(fmt.Sprintf("open upstream socket for %s: %v", client, err))
		return nil
	}
	r.upstreams[client.String()] = upstream
	r.wg.Add(1)
	go r.serveServer(upstream, client)
	return upstream
}

func (r *mkcpDNSHeaderRelay) serveServer(upstream *net.UDPConn, client *net.UDPAddr) {
	defer r.wg.Done()
	buffer := make([]byte, 65535)
	for {
		n, _, err := upstream.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		r.inspect("server -> client", buffer[:n])
		if _, err := r.listener.WriteToUDP(buffer[:n], client); err != nil {
			r.fail("forward a datagram from %s to %s: %v", r.server, client, err)
		}
	}
}

func (r *mkcpDNSHeaderRelay) inspect(direction string, datagram []byte) {
	var parser dnsmessage.Parser
	header, err := parser.Start(datagram)
	var question dnsmessage.Question
	if err == nil {
		question, err = parser.Question()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if direction == "client -> server" {
		r.toServer++
	} else {
		r.toClient++
	}
	if err == nil && !header.Response && question.Name.String() == r.name && question.Type == dnsmessage.TypeA && question.Class == dnsmessage.ClassINET {
		return
	}
	r.addProblemLocked(fmt.Sprintf("%s datagram %x does not start with a query for %s A IN: question %v, error %v", direction, datagram[:min(len(datagram), 48)], r.name, question, err))
}

// fail records a problem unless the relay is shutting down, when its sockets
// fail by design.
func (r *mkcpDNSHeaderRelay) fail(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.addProblemLocked(fmt.Sprintf(format, args...))
	}
}

func (r *mkcpDNSHeaderRelay) addProblemLocked(problem string) {
	if len(r.problems) < 5 {
		r.problems = append(r.problems, problem)
	} else {
		r.dropped++
	}
	select {
	case r.problemc <- struct{}{}:
	default:
	}
}

// takeProblems returns the problems recorded since the last call.
func (r *mkcpDNSHeaderRelay) takeProblems() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	problems := r.problems
	if r.dropped > 0 {
		problems = append(problems, fmt.Sprintf("and %d more relay problems", r.dropped))
	}
	r.problems, r.dropped = nil, 0
	return problems
}

func (r *mkcpDNSHeaderRelay) verify(t *testing.T) {
	t.Helper()
	problems := r.takeProblems()
	for _, problem := range problems {
		t.Error(problem)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.toServer == 0 || r.toClient == 0 {
		t.Errorf("relayed %d client and %d server datagrams, want both directions", r.toServer, r.toClient)
	}
	if len(problems) == 0 {
		t.Logf("relayed %d client and %d server datagrams, each starting with a query for %s A IN", r.toServer, r.toClient, r.name)
	}
}
