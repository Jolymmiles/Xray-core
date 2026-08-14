package scenarios

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCloseAllServersEscalatesStuckProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM escalation is Unix-specific")
	}

	command := exec.Command(os.Args[0], "-test.run=^TestCloseAllServersHelperProcess$")
	command.Env = append(os.Environ(), "XRAY_STUCK_SERVER_HELPER=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "ready" {
				ready <- nil
				return
			}
		}
		ready <- fmt.Errorf("helper readiness: %w", scanner.Err())
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("helper did not become ready")
	}

	start := time.Now()
	err = closeAllServers([]*exec.Cmd{command}, 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "killed after") {
		t.Fatalf("closeAllServers() error = %v, want forced-kill evidence", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("closeAllServers() took %s", elapsed)
	}
	if command.ProcessState == nil {
		t.Fatal("helper process was not reaped")
	}
}

func TestCloseAllServersHelperProcess(t *testing.T) {
	if os.Getenv("XRAY_STUCK_SERVER_HELPER") != "1" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	fmt.Println("ready")
	select {}
}
