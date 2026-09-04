//go:build unix

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type shutdownDuringStart struct {
	signal os.Signal
	closed string
}

func (*shutdownDuringStart) Type() interface{} { return (*shutdownDuringStart)(nil) }

func (f *shutdownDuringStart) Start() error {
	// Observe delivery while Start is still running. The CLI must already
	// subscribe too; registering after Start would lose this shutdown request.
	observed := make(chan os.Signal, 1)
	signal.Notify(observed, f.signal)
	defer signal.Stop(observed)
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	if err := process.Signal(f.signal); err != nil {
		return err
	}
	select {
	case <-observed:
		return nil
	case <-time.After(time.Second):
		return fmt.Errorf("startup signal was not delivered")
	}
}

func (f *shutdownDuringStart) Close() error {
	return os.WriteFile(f.closed, []byte("closed"), 0o600)
}

func TestShutdownSignalDuringStartup(t *testing.T) {
	if requested := os.Getenv("XRAY_TEST_STARTUP_SIGNAL"); requested != "" {
		var shutdown os.Signal = os.Interrupt
		if requested == "SIGTERM" {
			shutdown = syscall.SIGTERM
		}
		err := common.RegisterConfig(&emptypb.Empty{}, func(context.Context, interface{}) (interface{}, error) {
			return &shutdownDuringStart{signal: shutdown, closed: os.Getenv("XRAY_TEST_CLOSED_FILE")}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := proto.Marshal(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&emptypb.Empty{})}})
		if err != nil {
			t.Fatal(err)
		}
		config := filepath.Join(t.TempDir(), "startup.pb")
		if err := os.WriteFile(config, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		configFiles = cmdarg.Arg{config}
		*format = "protobuf"
		executeRun(cmdRun, nil)
		return
	}

	for _, requested := range []string{"SIGINT", "SIGTERM"} {
		t.Run(requested, func(t *testing.T) {
			closed := filepath.Join(t.TempDir(), "closed")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShutdownSignalDuringStartup$")
			child.Env = append(os.Environ(), "XRAY_TEST_STARTUP_SIGNAL="+requested, "XRAY_TEST_CLOSED_FILE="+closed)
			child.WaitDelay = time.Second
			if output, err := child.CombinedOutput(); err != nil {
				t.Fatalf("early %s did not shut Xray down cleanly: %v\n%s", requested, err, output)
			}
			if content, err := os.ReadFile(closed); err != nil || string(content) != "closed" {
				t.Fatalf("server Close was not completed: %q, %v", content, err)
			}
		})
	}
}
