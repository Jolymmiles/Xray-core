package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestShutdownAfterSignalIsBoundedWhileStdoutIsBlocked stops Xray while
// nobody reads its stdout, as when a supervisor stops reading the output of
// the process it signals. Xray's logger drops messages it cannot write, so
// such a process keeps relaying; its shutdown message must not hold it.
func TestShutdownAfterSignalIsBoundedWhileStdoutIsBlocked(t *testing.T) {
	t.Parallel()

	// The bounds xray run promises between a shutdown signal and its exit:
	// 10 s for Close, then 1 s for the message.
	const shutdownTimeout = 10 * time.Second
	const messageTimeout = time.Second
	const exitSlack = 5 * time.Second
	cases := []struct {
		behavior   string
		maxElapsed time.Duration
	}{
		{behavior: "fail", maxElapsed: messageTimeout + exitSlack},
		{behavior: "hang", maxElapsed: shutdownTimeout + messageTimeout + exitSlack},
	}
	for _, tc := range cases {
		t.Run(tc.behavior, func(t *testing.T) {
			t.Parallel()

			encoded, err := proto.Marshal(&core.Config{App: []*serial.TypedMessage{
				serial.ToTypedMessage(&wrapperspb.StringValue{Value: tc.behavior}),
			}})
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(t.TempDir(), "shutdown.pb")
			if err := os.WriteFile(config, encoded, 0o600); err != nil {
				t.Fatal(err)
			}

			// A non-blocking pipe lets the test fill it without blocking;
			// the child's Go runtime still parks a write to it until there
			// is room, like a write to a blocking pipe.
			var fds [2]int
			if err := syscall.Pipe2(fds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
				t.Fatal(err)
			}
			child := startShutdownChild(t, config, os.NewFile(uintptr(fds[0]), "stdout"), os.NewFile(uintptr(fds[1]), "stdout"), true)
			select {
			case <-child.started:
			case <-child.done:
				t.Fatalf("Xray exited before its features started\n%s", child.output())
			case <-time.After(5 * time.Second):
				t.Fatalf("Xray features did not start within 5s\n%s", child.output())
			}
			fillPipe(t, child.heldStdout)

			start := time.Now()
			if err := child.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case <-child.exited:
			case <-time.After(tc.maxElapsed):
				t.Fatalf("Xray with a full stdout was still running %s after SIGTERM", tc.maxElapsed)
			}
			if code := child.cmd.ProcessState.ExitCode(); code != 1 {
				t.Fatalf("exit code %d after %s, want 1", code, time.Since(start))
			}
		})
	}
}

// fillPipe writes to the non-blocking pipe end until the pipe has no room
// left, so the next write by any holder blocks.
func fillPipe(t *testing.T, pipe *os.File) {
	t.Helper()
	fd := int(pipe.Fd())
	line := []byte(strings.Repeat("x", 4095) + "\n")
	// Whole lines first; single bytes then take the last room a line no
	// longer fits in.
	for _, chunk := range [][]byte{line, line[len(line)-1:]} {
		for {
			_, err := syscall.Write(fd, chunk)
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
