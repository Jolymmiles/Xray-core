//go:build integration

package mtproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	command "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/serial"
)

const subprocessTimeout = 10 * time.Second

func TestMTProxySubprocess(t *testing.T) {
	binary := buildMTProxySubprocessBinary(t)
	for _, mode := range []string{"DD", "EE"} {
		t.Run(mode, func(t *testing.T) { testMTProxySubprocessRevoke(t, binary, mode) })
	}
	for _, ending := range []string{"client_eof", "cover_eof", "remove_inbound", "shutdown"} {
		t.Run("fallback_"+ending, func(t *testing.T) { testMTProxySubprocessFallback(t, binary, ending) })
	}
	t.Run("reject_invalid_clients", func(t *testing.T) { testMTProxySubprocessRejections(t, binary) })
}

func buildMTProxySubprocessBinary(t *testing.T) string {
	t.Helper()
	// Deliberately separate from XRAY_E2E_BIN: the main-branch binary may not
	// contain the unmerged MTProxy inbound at all.
	if binary := os.Getenv("XRAY_MTPROXY_E2E_BIN"); binary != "" {
		absolute, err := filepath.Abs(binary)
		if err != nil {
			t.Fatal(err)
		}
		return absolute
	}
	output := filepath.Join(t.TempDir(), "xray-mtproxy")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-trimpath", "-o", output, "./main")
	build.Dir = filepath.Join("..", "..")
	if logs, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build MTProxy Xray: %v\n%s", err, logs)
	}
	return output
}

type subprocessLog struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	started chan struct{}
	once    sync.Once
}

func (l *subprocessLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.buffer.Write(data)
	if strings.Contains(l.buffer.String(), "core: Xray ") && strings.Contains(l.buffer.String(), " started") {
		l.once.Do(func() { close(l.started) })
	}
	return n, err
}

func (l *subprocessLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.buffer.String() }

type mtproxySubprocess struct {
	command *exec.Cmd
	logs    *subprocessLog
	done    chan struct{}
	exitErr error
	address string
	api     command.HandlerServiceClient
}

func (p *mtproxySubprocess) stop(t *testing.T) {
	t.Helper()
	if p.command.Process == nil {
		return
	}
	select {
	case <-p.done:
		if p.exitErr != nil {
			t.Errorf("Xray exited before cleanup: %v", p.exitErr)
		}
		return
	default:
	}
	if err := p.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("stop Xray: %v", err)
	}
	select {
	case <-p.done:
		if p.exitErr != nil {
			t.Errorf("Xray shutdown: %v", p.exitErr)
		}
	case <-time.After(subprocessTimeout):
		_ = p.command.Process.Kill()
		<-p.done
		t.Error("Xray did not shut down before deadline")
	}
}

func startMTProxySubprocess(t *testing.T, binary string, middleAddress, coverAddress string) *mtproxySubprocess {
	t.Helper()
	directory := t.TempDir()
	secretPath := filepath.Join(directory, "proxy-secret")
	middleConfigPath := filepath.Join(directory, "proxy-multi.conf")
	upstreamSecret := bytes.Repeat([]byte{0x71}, 32)
	if err := os.WriteFile(secretPath, upstreamSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(middleConfigPath, []byte("proxy_for 2 "+middleAddress+";\ndefault 2;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Hold both reservations until configuration is ready so the selected ports
	// cannot alias. A bind race with an unrelated process is a failure, not retry.
	inboundReservation := subprocessListener(t)
	apiReservation := subprocessListener(t)
	inboundAddress := inboundReservation.Addr().String()
	apiAddress := apiReservation.Addr().String()
	firstSecret, secondSecret := testSecret(0x32), testSecret(0x52)
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"api": map[string]any{"tag": "api", "services": []string{"HandlerService"}},
		"inbounds": []any{
			map[string]any{"tag": "mtproxy", "listen": "127.0.0.1", "port": inboundReservation.Addr().(*net.TCPAddr).Port, "protocol": "mtproxy", "settings": map[string]any{
				"clients":  []any{map[string]any{"email": "revoke@example", "secret": hex.EncodeToString(firstSecret[:])}, map[string]any{"email": "keep@example", "secret": hex.EncodeToString(secondSecret[:])}},
				"upstream": map[string]any{"source": "files", "secretFile": secretPath, "configFile": middleConfigPath, "maxSessionsPerDC": 2, "maxClientsPerSession": 8},
				"fakeTLS":  map[string]any{"domains": []string{"cover.example"}, "serverHelloPayloadSize": 128},
			}},
			map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": apiReservation.Addr().(*net.TCPAddr).Port, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}},
		},
		"outbounds": []any{map[string]any{"tag": "cover", "protocol": "freedom", "settings": map[string]any{"redirect": coverAddress}}},
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"}}},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "xray.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	logs := &subprocessLog{started: make(chan struct{})}
	p := &mtproxySubprocess{command: exec.Command(binary, "run", "-config", configPath), logs: logs, done: make(chan struct{}), address: inboundAddress}
	p.command.Stdout, p.command.Stderr = logs, logs
	t.Cleanup(func() {
		p.stop(t)
		if t.Failed() {
			text := logs.String()
			for _, secret := range []string{hex.EncodeToString(firstSecret[:]), hex.EncodeToString(secondSecret[:]), hex.EncodeToString(upstreamSecret)} {
				text = strings.ReplaceAll(text, secret, "[test secret]")
			}
			t.Logf("Xray subprocess output:\n%s", text)
		}
	})
	if err := inboundReservation.Close(); err != nil {
		t.Fatal(err)
	}
	if err := apiReservation.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.exitErr = p.command.Wait(); close(p.done) }()
	// This marker means all core features finished Start. Application readiness
	// is established below by real RPC and complete client-to-Middle-End echo.
	select {
	case <-logs.started:
	case <-p.done:
		t.Fatalf("Xray exited during startup: %v", p.exitErr)
	case <-time.After(subprocessTimeout):
		t.Fatal("Xray startup deadline exceeded")
	}
	apiConnection, err := grpc.NewClient(apiAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = apiConnection.Close() })
	p.api = command.NewHandlerServiceClient(apiConnection)
	ctx, cancel := context.WithTimeout(t.Context(), subprocessTimeout)
	defer cancel()
	users, err := p.api.GetInboundUsersCount(ctx, &command.GetInboundUserRequest{Tag: "mtproxy"})
	if err != nil {
		t.Fatalf("HandlerService readiness: %v", err)
	}
	if users.Count != 2 {
		t.Fatalf("JSON client count = %d, want 2", users.Count)
	}
	return p
}

func subprocessListener(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func subprocessTCP(t *testing.T, address string) *net.TCPConn {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", address, subprocessTimeout)
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*net.TCPConn)
	t.Cleanup(func() { _ = tcp.Close() })
	if err := tcp.SetDeadline(time.Now().Add(subprocessTimeout)); err != nil {
		t.Fatal(err)
	}
	return tcp
}

type subprocessClient struct {
	connection *net.TCPConn
	encrypt    cipher.Stream
	reader     io.Reader
	fakeTLS    bool
}

func openSubprocessClient(t *testing.T, address, mode string, secret [16]byte) *subprocessClient {
	t.Helper()
	connection := subprocessTCP(t, address)
	if mode == "EE" {
		hello := fragmentClientHello(buildTestClientHello(t, secret, "cover.example", time.Now().Unix()), []int{3, 1, 7, 11, 23})
		if err := writeFull(connection, hello); err != nil {
			t.Fatal(err)
		}
		if err := consumeFakeTLSServerResponse(connection); err != nil {
			t.Fatal(err)
		}
		if err := writeFull(connection, []byte{0x14, 3, 3, 0, 1, 1}); err != nil {
			t.Fatal(err)
		}
	}
	header, encrypt, decrypt := buildClientHeader(t, secret, FrameModePaddedIntermediate, 2)
	var reader io.Reader = connection
	if mode == "EE" {
		if err := WriteFakeTLSApplicationData(connection, header[:], 32); err != nil {
			t.Fatal(err)
		}
		reader = NewFakeTLSRecordReader(connection, fakeTLSMaxRecordPayload)
	} else if err := writeFull(connection, header[:]); err != nil {
		t.Fatal(err)
	}
	return &subprocessClient{connection: connection, encrypt: encrypt, reader: &cipher.StreamReader{S: decrypt, R: reader}, fakeTLS: mode == "EE"}
}

func (c *subprocessClient) roundTrip(t *testing.T, payload []byte) {
	t.Helper()
	if err := c.connection.SetDeadline(time.Now().Add(subprocessTimeout)); err != nil {
		t.Fatal(err)
	}
	header, length, err := EncodeFrameHeader(FrameModePaddedIntermediate, len(payload), 2, false)
	if err != nil {
		t.Fatal(err)
	}
	frame := append(append(append([]byte(nil), header[:length]...), payload...), 0xaa, 0xbb)
	c.encrypt.XORKeyStream(frame, frame)
	if c.fakeTLS {
		err = WriteFakeTLSApplicationData(c.connection, frame, 64)
	} else {
		err = writeFull(c.connection, frame)
	}
	if err != nil {
		t.Fatal(err)
	}
	response, err := ReadFrameHeader(c.reader, FrameModePaddedIntermediate, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, response.WireLength)
	if _, err := io.ReadFull(c.reader, body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body[:response.PayloadLength], payload) {
		t.Fatal("subprocess changed MTProto payload")
	}
}

func assertSubprocessPeerClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(subprocessTimeout)); err != nil {
		t.Fatal(err)
	}
	var payload [1]byte
	n, err := connection.Read(payload[:])
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("peer did not close before deadline")
	}
	if n != 0 || err == nil {
		t.Fatalf("peer remained open: read %d bytes, error %v", n, err)
	}
}

type subprocessMiddle struct {
	listener   *net.TCPListener
	requests   chan ProxyRequest
	closed     chan uint64
	done       chan error
	mu         sync.Mutex
	connection net.Conn
	stopping   bool
}

func startSubprocessMiddle(t *testing.T) *subprocessMiddle {
	t.Helper()
	middle := &subprocessMiddle{listener: subprocessListener(t), requests: make(chan ProxyRequest, 16), closed: make(chan uint64, 16), done: make(chan error, 1)}
	t.Cleanup(func() {
		_ = middle.listener.Close()
		middle.mu.Lock()
		middle.stopping = true
		if middle.connection != nil {
			_ = middle.connection.Close()
		}
		middle.mu.Unlock()
		select {
		case err := <-middle.done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				t.Errorf("Middle-End fixture: %v", err)
			}
		case <-time.After(subprocessTimeout):
			t.Error("Middle-End fixture did not terminate")
		}
	})
	go func() { middle.done <- middle.serve() }()
	return middle
}

func (m *subprocessMiddle) serve() error {
	connection, err := m.listener.Accept()
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.stopping {
		m.mu.Unlock()
		_ = connection.Close()
		return net.ErrClosed
	}
	m.connection = connection
	m.mu.Unlock()
	defer connection.Close()
	secret := bytes.Repeat([]byte{0x71}, 32)
	wire, err := handshakeProcessMiddle(connection, secret)
	if err != nil {
		return err
	}

	for {
		encoded, err := wire.readMessage()
		if err != nil {
			return err
		}
		message, err := DecodeMiddleMessage(encoded, 1<<20)
		if err != nil {
			return err
		}
		switch message := message.(type) {
		case ProxyRequest:
			if message.Flags != 0x28021000 {
				return fmt.Errorf("unexpected request flags %#x", message.Flags)
			}
			if err := wire.writeMessage(EncodeProxyAnswer(ProxyAnswer{ConnectionID: message.ConnectionID, Payload: message.Payload})); err != nil {
				return err
			}
			m.requests <- message
		case CloseConnection:
			m.closed <- message.ConnectionID
		default:
			return fmt.Errorf("unexpected Middle-End request %T", message)
		}
	}
}

func (m *subprocessMiddle) request(t *testing.T) ProxyRequest {
	t.Helper()
	select {
	case request := <-m.requests:
		return request
	case <-time.After(subprocessTimeout):
		t.Fatal("Middle-End did not receive request")
		return ProxyRequest{}
	}
}

func testMTProxySubprocessRevoke(t *testing.T, binary, mode string) {
	middle := startSubprocessMiddle(t)
	cover := subprocessListener(t)
	p := startMTProxySubprocess(t, binary, middle.listener.Addr().String(), cover.Addr().String())
	first := openSubprocessClient(t, p.address, mode, testSecret(0x32))
	first.roundTrip(t, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	firstID := middle.request(t).ConnectionID
	second := openSubprocessClient(t, p.address, mode, testSecret(0x52))
	second.roundTrip(t, []byte{9, 10, 11, 12})
	secondID := middle.request(t).ConnectionID
	if firstID == secondID {
		t.Fatal("different clients shared a Middle-End logical ID")
	}
	ctx, cancel := context.WithTimeout(t.Context(), subprocessTimeout)
	defer cancel()
	if _, err := p.api.AlterInbound(ctx, &command.AlterInboundRequest{Tag: "mtproxy", Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: "revoke@example"})}); err != nil {
		t.Fatal(err)
	}
	assertSubprocessPeerClosed(t, first.connection)
	select {
	case id := <-middle.closed:
		if id != firstID {
			t.Fatalf("revoke closed %d, want %d", id, firstID)
		}
	case <-time.After(subprocessTimeout):
		t.Fatal("revoke did not reach Middle-End")
	}
	users, err := p.api.GetInboundUsersCount(ctx, &command.GetInboundUserRequest{Tag: "mtproxy"})
	if err != nil {
		t.Fatal(err)
	}
	if users.Count != 1 {
		t.Fatalf("user count after revoke = %d", users.Count)
	}
	second.roundTrip(t, bytes.Repeat([]byte{1, 2, 3, 4}, 4096))
	if id := middle.request(t).ConnectionID; id != secondID {
		t.Fatal("revoke replaced the unrelated logical client")
	}
	revoked := subprocessTCP(t, p.address)
	header, _, _ := buildClientHeader(t, testSecret(0x32), FrameModePaddedIntermediate, 2)
	if err := writeFull(revoked, header[:]); err != nil {
		t.Fatal(err)
	}
	assertSubprocessPeerClosed(t, revoked)
}

func testMTProxySubprocessFallback(t *testing.T, binary, ending string) {
	middle := subprocessListener(t)
	cover := subprocessListener(t)
	p := startMTProxySubprocess(t, binary, middle.Addr().String(), cover.Addr().String())
	client := subprocessTCP(t, p.address)
	hello := fragmentClientHello(buildTestClientHello(t, testSecret(0x7f), "cover.example", time.Now().Unix()), []int{3, 1, 7, 11, 23})
	wire := append(append([]byte(nil), hello...), []byte("coalesced fallback payload")...)
	if err := writeFull(client, wire); err != nil {
		t.Fatal(err)
	}
	if err := cover.SetDeadline(time.Now().Add(subprocessTimeout)); err != nil {
		t.Fatal(err)
	}
	coverConnection, err := cover.AcceptTCP()
	if err != nil {
		t.Fatalf("allowlisted fallback did not dial cover: %v", err)
	}
	t.Cleanup(func() { _ = coverConnection.Close() })
	if err := coverConnection.SetDeadline(time.Now().Add(subprocessTimeout)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(wire))
	if _, err := io.ReadFull(coverConnection, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatal("fallback changed fragmented ClientHello or coalesced payload bytes")
	}
	response := []byte("cover response over real dispatcher")
	if err := writeFull(coverConnection, response); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(response))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatal("fallback changed cover response")
	}
	switch ending {
	case "client_eof":
		if err := client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		assertSubprocessPeerClosed(t, coverConnection)
		assertSubprocessPeerClosed(t, client)
	case "cover_eof":
		if err := coverConnection.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		assertSubprocessPeerClosed(t, client)
		assertSubprocessPeerClosed(t, coverConnection)
	case "remove_inbound":
		ctx, cancel := context.WithTimeout(t.Context(), subprocessTimeout)
		defer cancel()
		if _, err := p.api.RemoveInbound(ctx, &command.RemoveInboundRequest{Tag: "mtproxy"}); err != nil {
			t.Fatal(err)
		}
		assertSubprocessPeerClosed(t, client)
		assertSubprocessPeerClosed(t, coverConnection)
	case "shutdown":
		p.stop(t)
		assertSubprocessPeerClosed(t, client)
		assertSubprocessPeerClosed(t, coverConnection)
	}
}

func testMTProxySubprocessRejections(t *testing.T, binary string) {
	middle := subprocessListener(t)
	cover := subprocessListener(t)
	p := startMTProxySubprocess(t, binary, middle.Addr().String(), cover.Addr().String())
	wrongHeader, _, _ := buildClientHeader(t, testSecret(0x7f), FrameModePaddedIntermediate, 2)
	cases := map[string][]byte{
		"wrong_secret":    wrongHeader[:],
		"unlisted_sni":    buildTestClientHello(t, testSecret(0x32), "unlisted.example", time.Now().Unix()),
		"malformed_hello": {0x16, 3, 1, 0, 4, 0xff, 0, 0, 0},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			client := subprocessTCP(t, p.address)
			if err := writeFull(client, wire); err != nil {
				t.Fatal(err)
			}
			assertSubprocessPeerClosed(t, client)
		})
	}
}
