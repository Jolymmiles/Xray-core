package scenarios

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/units"
	core "github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
)

func xor(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[i] = v ^ 'c'
	}
	return r
}

func readFrom(conn net.Conn, timeout time.Duration, length int) []byte {
	b := make([]byte, length)
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	n, err := io.ReadFull(conn, b[:length])
	if err != nil {
		fmt.Println("Unexpected error from readFrom:", err)
	}
	return b[:n]
}

func readFrom2(conn net.Conn, timeout time.Duration, length int) ([]byte, error) {
	b := make([]byte, length)
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	n, err := io.ReadFull(conn, b[:length])
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func InitializeServerConfigs(configs ...*core.Config) ([]*exec.Cmd, error) {
	servers := make([]*exec.Cmd, 0, 10)

	for _, config := range configs {
		server, err := InitializeServerConfig(config)
		if err != nil {
			CloseAllServers(servers)
			return nil, err
		}
		servers = append(servers, server)
	}

	time.Sleep(time.Second * 2)

	return servers, nil
}

func InitializeServerConfig(config *core.Config) (*exec.Cmd, error) {
	err := BuildXray()
	if err != nil {
		return nil, err
	}

	config = withDefaultApps(config)
	configBytes, err := proto.Marshal(config)
	if err != nil {
		return nil, err
	}
	proc := RunXrayProtobuf(configBytes)

	if err := proc.Start(); err != nil {
		return nil, err
	}

	return proc, nil
}

var (
	testBinaryPath    string
	testBinaryCleanFn func()
	testBinaryPathGen sync.Once
)

func genTestBinaryPath() {
	testBinaryPathGen.Do(func() {
		var tempDir string
		common.Must(retry.Timed(5, 100).On(func() error {
			dir, err := os.MkdirTemp("", "xray")
			if err != nil {
				return err
			}
			tempDir = dir
			testBinaryCleanFn = func() { os.RemoveAll(dir) }
			return nil
		}))
		file := filepath.Join(tempDir, "xray.test")
		if runtime.GOOS == "windows" {
			file += ".exe"
		}
		testBinaryPath = file
		fmt.Printf("Generated binary path: %s\n", file)
	})
}

func GetSourcePath() string {
	return filepath.Join("github.com", "xtls", "xray-core", "main")
}

const serverShutdownGrace = 5 * time.Second

func CloseAllServers(servers []*exec.Cmd) {
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Closing all servers.",
	})
	if err := closeAllServers(servers, serverShutdownGrace); err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  err.Error(),
		})
	}
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "All server closed.",
	})
}

func CloseServer(server *exec.Cmd) {
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Closing server.",
	})
	if err := closeAllServers([]*exec.Cmd{server}, serverShutdownGrace); err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  err.Error(),
		})
	}
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Server closed.",
	})
}

func closeAllServers(servers []*exec.Cmd, grace time.Duration) error {
	failures := make([]string, 0)
	for _, server := range servers {
		if server == nil || server.Process == nil {
			continue
		}
		var err error
		if runtime.GOOS == "windows" {
			err = server.Process.Kill()
		} else {
			err = server.Process.Signal(syscall.SIGTERM)
		}
		if err != nil && err != os.ErrProcessDone {
			failures = append(failures, fmt.Sprintf("signal server process %d: %v", server.Process.Pid, err))
		}
	}
	for _, server := range servers {
		if server == nil || server.Process == nil {
			continue
		}
		if err := waitForServerExit(server, grace); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("server cleanup: %s", strings.Join(failures, "; "))
	}
	return nil
}

func waitForServerExit(server *exec.Cmd, grace time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- server.Wait()
	}()

	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
	}

	if err := server.Process.Kill(); err != nil && err != os.ErrProcessDone {
		return fmt.Errorf("kill server process %d after %s: %w", server.Process.Pid, grace, err)
	}
	killTimer := time.NewTimer(grace)
	defer killTimer.Stop()
	select {
	case <-done:
		return fmt.Errorf("server process %d killed after %s", server.Process.Pid, grace)
	case <-killTimer.C:
		return fmt.Errorf("server process %d did not exit within %s after kill", server.Process.Pid, grace)
	}
}

func withDefaultApps(config *core.Config) *core.Config {
	config.App = append(config.App, serial.ToTypedMessage(&dispatcher.Config{}))
	config.App = append(config.App, serial.ToTypedMessage(&proxyman.InboundConfig{}))
	config.App = append(config.App, serial.ToTypedMessage(&proxyman.OutboundConfig{}))
	return config
}

func testTCPConn(port net.Port, payloadSize int, timeout time.Duration) func() error {
	return func() error {
		conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   []byte{127, 0, 0, 1},
			Port: int(port),
		})
		if err != nil {
			return err
		}
		defer conn.Close()

		return testTCPConn2(conn, payloadSize, timeout)()
	}
}

func testUDPConn(port net.Port, payloadSize int, timeout time.Duration) func() error {
	return func() error {
		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   []byte{127, 0, 0, 1},
			Port: int(port),
		})
		if err != nil {
			return err
		}
		defer conn.Close()

		return testTCPConn2(conn, payloadSize, timeout)()
	}
}

func waitForUDPPath(t *testing.T, port net.Port, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		probeTimeout := min(time.Second, time.Until(deadline))
		lastErr = testUDPConn(port, 64, probeTimeout)()
		if lastErr == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP path on port %d did not become ready within %s: %v", port, timeout, lastErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForTCPAndUDPPaths(t *testing.T, tcpPort, udpPort net.Port, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var tcpErr, udpErr error
	for {
		probeTimeout := min(time.Second, time.Until(deadline))
		tcpErr = testTCPConn(tcpPort, 64, probeTimeout)()
		udpErr = testUDPConn(udpPort, 64, probeTimeout)()
		if tcpErr == nil && udpErr == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("TCP/UDP paths on ports %d/%d did not become ready within %s: tcp=%v udp=%v", tcpPort, udpPort, timeout, tcpErr, udpErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func testTCPConn2(conn net.Conn, payloadSize int, timeout time.Duration) func() error {
	return func() (err1 error) {
		start := time.Now()
		defer func() {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			// For info on each, see: https://golang.org/pkg/runtime/#MemStats
			fmt.Println("testConn finishes:", time.Since(start).Milliseconds(), "ms\t",
				err1, "\tAlloc =", units.ByteSize(m.Alloc).String(),
				"\tTotalAlloc =", units.ByteSize(m.TotalAlloc).String(),
				"\tSys =", units.ByteSize(m.Sys).String(),
				"\tNumGC =", m.NumGC)
		}()
		singleWrite := func(length int) error {
			payload := make([]byte, length)
			common.Must2(rand.Read(payload))

			nBytes, err := conn.Write(payload)
			if err != nil {
				return err
			}
			if nBytes != len(payload) {
				return errors.New("expect ", len(payload), " written, but actually ", nBytes)
			}

			response, err := readFrom2(conn, timeout, length)
			if err != nil {
				return err
			}
			_ = response

			if r := bytes.Compare(response, xor(payload)); r != 0 {
				return errors.New(r)
			}

			return nil
		}
		for payloadSize > 0 {
			sizeToWrite := 1024
			if payloadSize < 1024 {
				sizeToWrite = payloadSize
			}
			if err := singleWrite(sizeToWrite); err != nil {
				return err
			}
			payloadSize -= sizeToWrite
		}
		return nil
	}
}

func WaitConnAvailableWithTest(t *testing.T, testFunc func() error) bool {
	for i := 1; ; i++ {
		if i > 10 {
			t.Log("All attempts failed to test tcp conn")
			return false
		}
		time.Sleep(time.Millisecond * 10)
		if err := testFunc(); err != nil {
			t.Log("err ", err)
		} else {
			t.Log("success with", i, "attempts")
			break
		}
	}
	return true
}
