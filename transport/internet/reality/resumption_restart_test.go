package reality

import (
	"bufio"
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// The environment of the process TestRestartedServerChild runs as a REALITY
// server restarted with the parent's configuration.
const (
	restartedServerKey    = "REALITY_RESTARTED_SERVER_KEY"
	restartedServerTarget = "REALITY_RESTARTED_SERVER_TARGET"
	restartedServerCA     = "REALITY_RESTARTED_SERVER_CA"
)

// TestRestartedServerChild is the restarted server of
// TestRestartedServerDoesNotResumeAReplayedHello: a new process with the
// same private key and target, which prints its address and serves until
// its standard input closes.
func TestRestartedServerChild(t *testing.T) {
	if os.Getenv(restartedServerKey) == "" {
		t.Skip("runs only as the restarted server of TestRestartedServerDoesNotResumeAReplayedHello")
	}
	// The parent's target has the parent's certificate.
	os.Setenv("SSL_CERT_FILE", os.Getenv(restartedServerCA))
	key, err := hex.DecodeString(os.Getenv(restartedServerKey))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	server := startRealityServerWithKey(t, os.Getenv(restartedServerTarget), priv)
	fmt.Printf("ADDR %s\n", server.addr)
	io.Copy(io.Discard, os.Stdin)
}

// startRestartedServer runs server's configuration in a new process, as
// after a restart, and returns its address once it serves.
func startRestartedServer(t *testing.T, target string, server *realityServer) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestartedServerChild$", "-test.timeout=2m")
	cmd.Env = append(os.Environ(),
		restartedServerKey+"="+hex.EncodeToString(server.config.PrivateKey.Bytes()),
		restartedServerTarget+"="+target,
		restartedServerCA+"="+os.Getenv("SSL_CERT_FILE"))
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if addr, ok := strings.CutPrefix(scanner.Text(), "ADDR "); ok {
				ready <- addr
			}
		}
		close(ready)
	}()
	select {
	case addr, ok := <-ready:
		if !ok {
			t.Fatal("the restarted server exited before it served")
		}
		return addr
	case <-time.After(90 * time.Second):
		t.Fatal("the restarted server did not start")
		return ""
	}
}

// A censor that records a resumed ClientHello and replays it after the
// server restarts, when the restarted process has no record of the hello,
// gets what the target answers to those bytes: a full handshake. The
// target never issued the ticket, so it never resumes it.
func TestRestartedServerDoesNotResumeAReplayedHello(t *testing.T) {
	target := goTarget(t)
	server := startRealityServer(t, target)
	hello := dialResumedHello(t, server)
	restarted := startRestartedServer(t, target, server)

	replayed, direct := answer(t, restarted, hello), answer(t, target, hello)
	if len(replayed) == 0 || len(direct) == 0 {
		t.Fatalf("no answer: replayed %d records, target %d", len(replayed), len(direct))
	}
	got, want := serverHelloExtensions(t, replayed[0]), serverHelloExtensions(t, direct[0])
	if slices.Contains(got, 41) || !slices.Equal(got, want) {
		t.Fatalf("hello replayed after a restart: ServerHello extensions %v, the target's %v", got, want)
	}
	if len(replayed) != len(direct) {
		t.Fatalf("hello replayed after a restart: %d records, the target's %d", len(replayed), len(direct))
	}
}
