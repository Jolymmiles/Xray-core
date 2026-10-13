//go:build linux && !coverage

// Linux only: the hanging download trusts its fixture through SSL_CERT_FILE,
// which macOS certificate verification ignores.

package scenarios

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/testing/servers/tcp"
)

// shutdownTimeout is the bound xray run promises between a shutdown signal
// and its exit.
const shutdownTimeout = 10 * time.Second

// TestShutdownSignalEndsProxyingWhenCloseHangs stops Xray while app/geodata
// downloads an asset whose body never ends. The download runs on a context
// nothing cancels and reads until EOF, so geodata's Close waits for it. Xray
// used to keep relaying established connections and to ignore further
// SIGTERMs until it was killed.
func TestShutdownSignalEndsProxyingWhenCloseHangs(t *testing.T) {
	assets := t.TempDir()
	if err := os.WriteFile(filepath.Join(assets, "test.dat"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	downloading := make(chan struct{})
	var downloadStarted sync.Once
	stopDownload := make(chan struct{})
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := w.Write([]byte{0}); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			downloadStarted.Do(func() { close(downloading) })
			select {
			case <-r.Context().Done():
				return
			case <-stopDownload:
				return
			case <-ticker.C:
			}
		}
	}))
	fixture.EnableHTTP2 = true
	fixture.StartTLS()
	t.Cleanup(fixture.Close)
	t.Cleanup(func() { close(stopDownload) })
	certificate := filepath.Join(t.TempDir(), "fixture.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	xray, held := startRelayingXray(t, map[string]any{
		"cron":     "@every 1s",
		"outbound": "direct",
		"assets":   []any{map[string]any{"url": fixture.URL + "/test.dat", "file": "test.dat"}},
	}, "XRAY_LOCATION_ASSET="+assets, "SSL_CERT_FILE="+certificate)
	select {
	case <-downloading:
	case <-xray.done:
		t.Fatalf("Xray exited before it started the download\n%s", xray.output())
	case <-time.After(10 * time.Second):
		t.Fatalf("Xray did not start the geodata download within 10s\n%s", xray.output())
	}

	start := time.Now()
	if err := xray.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if !xray.exitedWithin(shutdownTimeout + 5*time.Second) {
		t.Fatalf("Xray was still running %s after SIGTERM; an established connection still relayed data: %t\n%s",
			time.Since(start).Round(time.Second), echoes(held) == nil, xray.output())
	}
	elapsed := time.Since(start)

	if code := xray.cmd.ProcessState.ExitCode(); code != 1 {
		t.Fatalf("exit code %d, want 1\n%s", code, xray.output())
	}
	if elapsed < shutdownTimeout {
		t.Fatalf("Xray exited %s after SIGTERM, before the %s close timeout\n%s", elapsed, shutdownTimeout, xray.output())
	}
	if !strings.Contains(xray.output(), "Timed out while closing Xray.") {
		t.Fatalf("output lacks the close timeout\n%s", xray.output())
	}
	requireClosedByPeer(t, held)
	if content, err := os.ReadFile(filepath.Join(assets, "test.dat")); err != nil || string(content) != "original" {
		t.Fatalf("asset changed by the abandoned download: %q, %v", content, err)
	}
}

// TestShutdownSignalClosesRelayingXray is the control: without a feature
// that blocks Close, SIGTERM ends Xray at once and cleanly.
func TestShutdownSignalClosesRelayingXray(t *testing.T) {
	xray, held := startRelayingXray(t, nil)

	start := time.Now()
	if err := xray.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if !xray.exitedWithin(2 * time.Second) {
		t.Fatalf("Xray was still running %s after SIGTERM\n%s", time.Since(start).Round(time.Second), xray.output())
	}
	if code := xray.cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("exit code %d, want 0\n%s", code, xray.output())
	}
	requireClosedByPeer(t, held)
}

type xrayProcess struct {
	cmd *exec.Cmd
	// done is closed after Xray exited and its output was read.
	done chan struct{}

	mu      sync.Mutex
	stdout  bytes.Buffer
	readErr error
}

// startRelayingXray builds Xray and runs it with a JSON config whose
// dokodemo-door inbound relays to a TCP echo server through freedom. It
// returns once a connection through Xray echoes, with that connection still
// open. geodata, when not nil, is the config's geodata object.
func startRelayingXray(t *testing.T, geodata map[string]any, env ...string) (*xrayProcess, net.Conn) {
	t.Helper()
	if err := BuildXray(); err != nil {
		t.Fatal(err)
	}

	echo := tcp.Server{MsgProcessor: xor}
	dest, err := echo.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })

	port := tcp.PickPort()
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     int(port),
			"protocol": "dokodemo-door",
			"settings": map[string]any{"address": dest.Address.String(), "port": int(dest.Port), "network": "tcp"},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	if geodata != nil {
		config["geodata"] = geodata
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	xray := &xrayProcess{cmd: exec.Command(testBinaryPath, "run", "-c", configPath), done: make(chan struct{})}
	xray.cmd.Env = append(os.Environ(), env...)
	xray.cmd.Stdout = writer
	xray.cmd.Stderr = writer
	if err := xray.cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()
	outputRead := make(chan struct{})
	go func() {
		defer close(outputRead)
		defer reader.Close()
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			xray.mu.Lock()
			xray.stdout.WriteString(scanner.Text() + "\n")
			xray.mu.Unlock()
		}
		xray.readErr = scanner.Err()
	}()
	go func() {
		_ = xray.cmd.Wait()
		<-outputRead
		close(xray.done)
	}()
	t.Cleanup(func() {
		select {
		case <-xray.done:
		default:
			if err := xray.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill Xray: %v", err)
			}
			select {
			case <-xray.done:
			case <-time.After(5 * time.Second):
				t.Errorf("Xray output was not closed within 5s after SIGKILL\n%s", xray.output())
				return
			}
		}
		if xray.readErr != nil {
			t.Errorf("read Xray output: %v", xray.readErr)
		}
	})

	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	deadline := time.After(10 * time.Second)
	retry := time.NewTicker(50 * time.Millisecond)
	defer retry.Stop()
	for {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			if err = echoes(conn); err == nil {
				t.Cleanup(func() { conn.Close() })
				return xray, conn
			}
			conn.Close()
		}
		select {
		case <-xray.done:
			t.Fatalf("Xray exited before it relayed a connection: %v\n%s", err, xray.output())
		case <-deadline:
			t.Fatalf("no connection through Xray echoed within 10s: %v\n%s", err, xray.output())
		case <-retry.C:
		}
	}
}

func (x *xrayProcess) exitedWithin(timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-x.done:
		return true
	case <-timer.C:
		return false
	}
}

func (x *xrayProcess) output() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.stdout.String()
}

// echoes sends a message through conn and checks the echo server's reply.
func echoes(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	message := []byte("relay")
	if _, err := conn.Write(message); err != nil {
		return err
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if !bytes.Equal(reply, xor(message)) {
		return errors.New("unexpected echo")
	}
	return nil
}

// requireClosedByPeer checks that Xray's exit closed a connection it relayed.
func requireClosedByPeer(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := conn.Read(make([]byte, 1))
	var netErr net.Error
	if err == nil || errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("a connection Xray relayed stayed open after Xray exited: %v", err)
	}
}
