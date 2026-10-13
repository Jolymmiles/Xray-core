//go:build unix

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const closeTestFeatureStarted = "close test feature started"

// closeTestFeature closes as its config says: "ok" returns nil, "fail"
// returns an error and "hang" never returns, like a feature whose Close
// waits for work that does not end.
type closeTestFeature struct {
	behavior string
}

func (*closeTestFeature) Type() interface{} { return (*closeTestFeature)(nil) }

func (*closeTestFeature) Start() error {
	fmt.Println(closeTestFeatureStarted)
	return nil
}

func (f *closeTestFeature) Close() error {
	switch f.behavior {
	case "fail":
		return errors.New("close test feature failed")
	case "hang":
		<-make(chan struct{})
	}
	return nil
}

func TestShutdownAfterSignalIsBounded(t *testing.T) {
	if config := os.Getenv("XRAY_TEST_SHUTDOWN_CONFIG"); config != "" {
		err := common.RegisterConfig(&wrapperspb.StringValue{}, func(_ context.Context, config interface{}) (interface{}, error) {
			return &closeTestFeature{behavior: config.(*wrapperspb.StringValue).GetValue()}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		configFiles = cmdarg.Arg{config}
		*format = "protobuf"
		executeRun(cmdRun, nil)
		return
	}
	t.Parallel()

	// The bound xray run promises between a shutdown signal and its exit.
	const shutdownTimeout = 10 * time.Second
	const fastExit = 2 * time.Second
	const exitSlack = 5 * time.Second
	cases := []struct {
		behavior   string
		code       int
		message    string
		minElapsed time.Duration
		maxElapsed time.Duration
	}{
		{behavior: "ok", code: 0, maxElapsed: fastExit},
		{behavior: "fail", code: 1, message: "Failed to close:", maxElapsed: fastExit},
		{behavior: "hang", code: 1, message: "Timed out while closing Xray.", minElapsed: shutdownTimeout, maxElapsed: shutdownTimeout + exitSlack},
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

			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			child := startShutdownChild(t, config, reader, writer, false)
			select {
			case <-child.started:
			case <-child.done:
				t.Fatalf("Xray exited before its features started\n%s", child.output())
			case <-time.After(5 * time.Second):
				t.Fatalf("Xray features did not start within 5s\n%s", child.output())
			}

			start := time.Now()
			if err := child.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case <-child.done:
			case <-time.After(tc.maxElapsed):
				t.Fatalf("Xray was still running %s after SIGTERM\n%s", tc.maxElapsed, child.output())
			}
			elapsed := time.Since(start)

			if code := child.cmd.ProcessState.ExitCode(); code != tc.code {
				t.Fatalf("exit code %d, want %d\n%s", code, tc.code, child.output())
			}
			if elapsed < tc.minElapsed {
				t.Fatalf("Xray exited %s after SIGTERM, before the %s close timeout\n%s", elapsed, tc.minElapsed, child.output())
			}
			if tc.message != "" && !strings.Contains(child.output(), tc.message) {
				t.Fatalf("output lacks %q\n%s", tc.message, child.output())
			}
		})
	}
}

type shutdownChild struct {
	cmd *exec.Cmd
	// started is closed when the child prints closeTestFeatureStarted.
	started chan struct{}
	// exited is closed when the child exited; done once its output was read.
	exited chan struct{}
	done   chan struct{}
	// heldStdout is the test's end of the child's stdout pipe while the test
	// holds the output; see startShutdownChild.
	heldStdout *os.File

	mu      sync.Mutex
	stdout  strings.Builder
	readErr error
}

// startShutdownChild runs executeRun in a copy of the test binary with its
// config at config, stdout and stderr on the pipe reader and writer, and
// takes both. With holdOutput the test stops reading the pipe after the
// child's features started, until the child exits, and keeps writer open as
// heldStdout. The child is killed when the test ends if it is still running.
func startShutdownChild(t *testing.T, config string, reader, writer *os.File, holdOutput bool) *shutdownChild {
	t.Helper()
	child := &shutdownChild{
		cmd:     exec.Command(os.Args[0], "-test.run=^TestShutdownAfterSignalIsBounded$"),
		started: make(chan struct{}),
		exited:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	child.cmd.Env = append(os.Environ(), "XRAY_TEST_SHUTDOWN_CONFIG="+config)
	child.cmd.Stdout = writer
	child.cmd.Stderr = writer
	if err := child.cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	if holdOutput {
		child.heldStdout = writer
	} else {
		writer.Close()
	}

	outputRead := make(chan struct{})
	go func() {
		defer close(outputRead)
		defer reader.Close()
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
			child.mu.Lock()
			child.stdout.WriteString(line + "\n")
			child.mu.Unlock()
			if line == closeTestFeatureStarted {
				close(child.started)
				if holdOutput {
					<-child.exited
				}
			}
		}
		child.readErr = scanner.Err()
	}()
	go func() {
		_ = child.cmd.Wait()
		close(child.exited)
		<-outputRead
		close(child.done)
	}()
	t.Cleanup(func() {
		if child.heldStdout != nil {
			child.heldStdout.Close()
		}
		select {
		case <-child.done:
		default:
			if err := child.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill Xray: %v", err)
			}
			select {
			case <-child.done:
			case <-time.After(5 * time.Second):
				t.Errorf("Xray output was not closed within 5s after SIGKILL\n%s", child.output())
				return
			}
		}
		if child.readErr != nil {
			t.Errorf("read Xray output: %v", child.readErr)
		}
	})
	return child
}

func (c *shutdownChild) output() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stdout.String()
}
