//go:build integration

package singmux_test

import (
	"bytes"
	cryptotls "crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestVLESSShortConnectionStability(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level VLESS short-connection stability test")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(t, workDir)
	responseServer := startShortResponseTCPServer(t)
	tlsResponseServer := startShortResponseTLSServer(t, certificate, privateKey)

	for _, security := range []string{"tls", "reality"} {
		for _, flow := range []string{"", "xtls-rprx-vision"} {
			flowName := "no-flow"
			if flow != "" {
				flowName = "vision"
			}
			t.Run(filepath.Join(security, flowName), func(t *testing.T) {
				runVLESSShortConnectionScenario(t, workDir, xray, certificate, privateKey, security, flow, responseServer, tlsResponseServer)
			})
		}
	}
	if !t.Failed() {
		t.Log("VLESS_SHORT_CONNECTION_STABILITY_OK")
	}
}

func TestVLESSShortConnectionBurstStress(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level VLESS short-connection burst stress")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(t, workDir)
	destination := startShortResponseTCPServer(t)
	for _, security := range []string{"tls", "reality"} {
		for _, flow := range []string{"", "xtls-rprx-vision"} {
			flowName := "no-flow"
			if flow != "" {
				flowName = "vision"
			}
			t.Run(filepath.Join(security, flowName), func(t *testing.T) {
				runVLESSShortConnectionBurst(t, workDir, xray, certificate, privateKey, security, flow, destination)
			})
		}
	}
	if !t.Failed() {
		t.Log("VLESS_SHORT_CONNECTION_BURST_OK")
	}
}

func runVLESSShortConnectionBurst(t *testing.T, workDir, xray, certificate, privateKey, security, flow string, destination *net.TCPAddr) {
	t.Helper()
	serverPort := freeTCPPort(t)
	socksPort := freeTCPPort(t)
	flowName := "no-flow"
	if flow != "" {
		flowName = "vision"
	}
	scenarioDir := filepath.Join(workDir, "burst-"+security+"-"+flowName)
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realityTarget := ""
	if security == "reality" {
		realityTarget = startRealityCoverServer(t, certificate, privateKey)
	}
	serverPath := filepath.Join(scenarioDir, "server.json")
	clientPath := filepath.Join(scenarioDir, "client.json")
	writeConfig(t, serverPath, xrayVLESSTCPConfig(t, true, serverPort, 0, security, flow, certificate, privateKey, realityTarget))
	writeConfig(t, clientPath, xrayVLESSTCPConfig(t, false, serverPort, socksPort, security, flow, certificate, "", ""))
	server := startE2EProcess(t, xray, "run", "-config", serverPath)
	waitTCP(t, server, serverPort)
	client := startE2EProcess(t, xray, "run", "-config", clientPath)
	waitSOCKS(t, client, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
			t.Logf("client logs:\n%s", client.logs.String())
		}
	})
	if err := runShortSOCKSRequest(socksPort, destination, 0, false); err != nil {
		t.Fatalf("full-path readiness request: %v", err)
	}

	const attempts = 64
	errorsByAttempt := make(chan error, attempts)
	var group sync.WaitGroup
	group.Add(attempts)
	for attempt := range attempts {
		go func() {
			defer group.Done()
			halfClose := attempt%2 != 0
			if err := runShortSOCKSRequest(socksPort, destination, uint32(attempt+1), halfClose); err != nil {
				errorsByAttempt <- fmt.Errorf("attempt %d (half-close=%t): %w", attempt, halfClose, err)
			}
		}()
	}
	group.Wait()
	close(errorsByAttempt)
	for err := range errorsByAttempt {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	if err := runShortSOCKSRequest(socksPort, destination, attempts+1, false); err != nil {
		t.Fatalf("follow-up connection after burst: %v", err)
	}
}

func runVLESSShortConnectionScenario(t *testing.T, workDir, xray, certificate, privateKey, security, flow string, destination, tlsDestination *net.TCPAddr) {
	t.Helper()
	serverPort := freeTCPPort(t)
	socksPort := freeTCPPort(t)
	scenarioDir := filepath.Join(workDir, "short-"+security+"-"+filepath.Base(t.Name()))
	if err := os.MkdirAll(scenarioDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realityTarget := ""
	if security == "reality" {
		realityTarget = startRealityCoverServer(t, certificate, privateKey)
	}
	serverPath := filepath.Join(scenarioDir, "server.json")
	clientPath := filepath.Join(scenarioDir, "client.json")
	writeConfig(t, serverPath, xrayVLESSTCPConfig(t, true, serverPort, 0, security, flow, certificate, privateKey, realityTarget))
	writeConfig(t, clientPath, xrayVLESSTCPConfig(t, false, serverPort, socksPort, security, flow, certificate, "", ""))
	server := startE2EProcess(t, xray, "run", "-config", serverPath)
	waitTCP(t, server, serverPort)
	client := startE2EProcess(t, xray, "run", "-config", clientPath)
	waitSOCKS(t, client, socksPort)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
			t.Logf("client logs:\n%s", client.logs.String())
		}
	})

	if err := runShortSOCKSRequest(socksPort, destination, 0, false); err != nil {
		t.Fatalf("full-path readiness request: %v", err)
	}
	if err := runShortSOCKSRequest(socksPort, destination, 1, true); err != nil {
		t.Fatalf("half-closed request: %v", err)
	}
	if err := runShortSOCKSRequest(socksPort, destination, 2, false); err != nil {
		t.Fatalf("follow-up connection after half-close: %v", err)
	}
	if flow != "" {
		if err := runShortTLSSOCKSRequest(socksPort, tlsDestination, 3); err != nil {
			t.Fatalf("inner TLS half-closed connection: %v", err)
		}
	}
}

type shortResponseServer struct {
	listener net.Listener
	mu       sync.Mutex
	active   map[net.Conn]struct{}
	errors   []error
	workers  sync.WaitGroup
}

func startShortResponseTCPServer(t testing.TB) *net.TCPAddr {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return startShortResponseServer(t, listener)
}

func startShortResponseTLSServer(t testing.TB, certificate, privateKey string) *net.TCPAddr {
	t.Helper()
	pair, err := cryptotls.LoadX509KeyPair(certificate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := cryptotls.Listen("tcp4", "127.0.0.1:0", &cryptotls.Config{
		Certificates: []cryptotls.Certificate{pair},
		MinVersion:   cryptotls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	return startShortResponseServer(t, listener)
}

func startShortResponseServer(t testing.TB, listener net.Listener) *net.TCPAddr {
	t.Helper()
	server := &shortResponseServer{
		listener: listener,
		active:   make(map[net.Conn]struct{}),
	}
	server.workers.Add(1)
	go server.accept()
	t.Cleanup(func() {
		server.close()
		server.mu.Lock()
		defer server.mu.Unlock()
		for _, err := range server.errors {
			t.Errorf("short-response server: %v", err)
		}
	})
	return listener.Addr().(*net.TCPAddr)
}

func (s *shortResponseServer) accept() {
	defer s.workers.Done()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.mu.Lock()
				s.errors = append(s.errors, fmt.Errorf("accept: %w", err))
				s.mu.Unlock()
			}
			return
		}
		s.mu.Lock()
		s.active[connection] = struct{}{}
		s.mu.Unlock()
		s.workers.Add(1)
		go s.serve(connection)
	}
}

func (s *shortResponseServer) serve(connection net.Conn) {
	defer s.workers.Done()
	defer func() {
		_ = connection.Close()
		s.mu.Lock()
		delete(s.active, connection)
		s.mu.Unlock()
	}()
	if err := serveShortResponse(connection); err != nil {
		s.mu.Lock()
		s.errors = append(s.errors, err)
		s.mu.Unlock()
	}
}

func (s *shortResponseServer) close() {
	_ = s.listener.Close()
	s.mu.Lock()
	for connection := range s.active {
		_ = connection.Close()
	}
	s.mu.Unlock()
	s.workers.Wait()
}

func serveShortResponse(connection net.Conn) error {
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	request := make([]byte, 5)
	if _, err := io.ReadFull(connection, request); err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if request[0] == 1 {
		if _, err := io.Copy(io.Discard, connection); err != nil {
			return fmt.Errorf("read request EOF: %w", err)
		}
	}
	response := shortConnectionResponse(binary.BigEndian.Uint32(request[1:]))
	for len(response) > 0 {
		written, err := connection.Write(response)
		if err != nil {
			return fmt.Errorf("write response: %w", err)
		}
		response = response[written:]
	}
	return nil
}

func runShortTLSSOCKSRequest(socksPort int, destination *net.TCPAddr, attempt uint32) error {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial SOCKS: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	if err := socksGreeting(connection); err != nil {
		return fmt.Errorf("SOCKS greeting: %w", err)
	}
	connectRequest := append([]byte{5, 1, 0, 1}, destination.IP.To4()...)
	connectRequest = binary.BigEndian.AppendUint16(connectRequest, uint16(destination.Port))
	if _, err := connection.Write(connectRequest); err != nil {
		return fmt.Errorf("SOCKS connect request: %w", err)
	}
	if err := readSOCKSReply(connection); err != nil {
		return fmt.Errorf("SOCKS connect reply: %w", err)
	}
	tlsConnection := cryptotls.Client(connection, &cryptotls.Config{
		InsecureSkipVerify: true, // generated loopback certificate
		MinVersion:         cryptotls.VersionTLS13,
		ServerName:         "localhost",
	})
	if err := tlsConnection.Handshake(); err != nil {
		return fmt.Errorf("inner TLS handshake: %w", err)
	}
	request := make([]byte, 5)
	request[0] = 1
	binary.BigEndian.PutUint32(request[1:], attempt)
	if _, err := tlsConnection.Write(request[:1]); err != nil {
		return fmt.Errorf("write first inner TLS request record: %w", err)
	}
	if _, err := tlsConnection.Write(request[1:]); err != nil {
		return fmt.Errorf("write second inner TLS request record: %w", err)
	}
	if err := tlsConnection.CloseWrite(); err != nil {
		return fmt.Errorf("close inner TLS write side: %w", err)
	}
	tcpConnection, ok := connection.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("SOCKS connection type %T does not support CloseWrite", connection)
	}
	if err := tcpConnection.CloseWrite(); err != nil {
		return fmt.Errorf("half-close outer request stream: %w", err)
	}
	want := shortConnectionResponse(attempt)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(tlsConnection, got); err != nil {
		return fmt.Errorf("read %d-byte inner TLS response: %w", len(want), err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("inner TLS response changed")
	}
	return nil
}

func runShortSOCKSRequest(socksPort int, destination *net.TCPAddr, attempt uint32, halfClose bool) error {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial SOCKS: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	if err := socksGreeting(connection); err != nil {
		return fmt.Errorf("SOCKS greeting: %w", err)
	}
	request := append([]byte{5, 1, 0, 1}, destination.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(destination.Port))
	if _, err := connection.Write(request); err != nil {
		return fmt.Errorf("SOCKS connect request: %w", err)
	}
	if err := readSOCKSReply(connection); err != nil {
		return fmt.Errorf("SOCKS connect reply: %w", err)
	}
	requestPayload := make([]byte, 5)
	if halfClose {
		requestPayload[0] = 1
	}
	binary.BigEndian.PutUint32(requestPayload[1:], attempt)
	if _, err := connection.Write(requestPayload); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if halfClose {
		tcpConnection, ok := connection.(*net.TCPConn)
		if !ok {
			return fmt.Errorf("SOCKS connection type %T does not support CloseWrite", connection)
		}
		if err := tcpConnection.CloseWrite(); err != nil {
			return fmt.Errorf("half-close request: %w", err)
		}
	}
	want := shortConnectionResponse(attempt)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(connection, got); err != nil {
		return fmt.Errorf("read %d-byte response: %w", len(want), err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("short-connection response changed")
	}
	var trailing [1]byte
	if _, err := connection.Read(trailing[:]); !errors.Is(err, io.EOF) {
		return fmt.Errorf("read terminal EOF: %v", err)
	}
	return nil
}

func shortConnectionResponse(attempt uint32) []byte {
	pattern := []byte{
		byte(attempt >> 24), byte(attempt >> 16), byte(attempt >> 8), byte(attempt),
		'v', 'l', 'e', 's', 's', '-', 's', 'h', 'o', 'r', 't', '-',
	}
	return bytes.Repeat(pattern, 4096)
}

func TestShortOriginHalfCloseControl(t *testing.T) {
	destination := startShortResponseTCPServer(t)
	if err := runDirectShortRequest(destination.Port, 0, false); err != nil {
		t.Fatalf("direct origin readiness: %v", err)
	}
	if err := runDirectShortRequest(destination.Port, 1, true); err != nil {
		t.Fatalf("direct origin half-close: %v", err)
	}
}

func TestShortSOCKSHalfCloseControl(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level SOCKS half-close control")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	socksPort := freeTCPPort(t)
	destination := startShortResponseTCPServer(t)
	configPath := filepath.Join(workDir, "socks-freedom.json")
	writeConfig(t, configPath, shortSOCKSFreedomConfig(t, socksPort))
	process := startE2EProcess(t, xray, "run", "-config", configPath)
	waitSOCKS(t, process, socksPort)
	if err := runShortSOCKSRequest(socksPort, destination, 0, false); err != nil {
		t.Fatalf("plain SOCKS/freedom readiness: %v\nlogs:\n%s", err, process.logs.String())
	}
	if err := runShortSOCKSRequest(socksPort, destination, 1, true); err != nil {
		t.Fatalf("plain SOCKS/freedom half-close: %v\nlogs:\n%s", err, process.logs.String())
	}
}

func shortSOCKSFreedomConfig(t testing.TB, socksPort int) []byte {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDokodemoHalfCloseControl(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level dokodemo half-close control")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	inboundPort := freeTCPPort(t)
	destination := startShortResponseTCPServer(t)
	configPath := filepath.Join(workDir, "dokodemo-freedom.json")
	writeConfig(t, configPath, shortDokodemoFreedomConfig(t, inboundPort, destination))
	process := startE2EProcess(t, xray, "run", "-config", configPath)
	waitProcessLog(t, process, "started")
	if err := runDirectShortRequest(inboundPort, 0, false); err != nil {
		t.Fatalf("dokodemo/freedom readiness: %v\nlogs:\n%s", err, process.logs.String())
	}
	if err := runDirectShortRequest(inboundPort, 1, true); err != nil {
		t.Fatalf("dokodemo/freedom half-close: %v\nlogs:\n%s", err, process.logs.String())
	}
}

func shortDokodemoFreedomConfig(t testing.TB, inboundPort int, destination *net.TCPAddr) []byte {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": inboundPort, "protocol": "dokodemo-door",
			"settings": map[string]any{
				"address": destination.IP.String(), "port": destination.Port, "network": "tcp",
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func runDirectShortRequest(port int, attempt uint32, halfClose bool) error {
	connection, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return fmt.Errorf("dial direct inbound: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	request := make([]byte, 5)
	if halfClose {
		request[0] = 1
	}
	binary.BigEndian.PutUint32(request[1:], attempt)
	if _, err := connection.Write(request); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if halfClose {
		if err := connection.CloseWrite(); err != nil {
			return fmt.Errorf("half-close request: %w", err)
		}
	}
	want := shortConnectionResponse(attempt)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(connection, got); err != nil {
		return fmt.Errorf("read %d-byte response: %w", len(want), err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("direct short-connection response changed")
	}
	return nil
}
