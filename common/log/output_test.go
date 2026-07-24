package log_test

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	corelog "github.com/xtls/xray-core/common/log"
)

func TestConsoleOutputWritesBatchWithoutClosingProcessWriter(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	output := corelog.NewConsoleOutput(writer)
	if err := output.WriteBatch([][]byte{[]byte("one\n"), []byte("two\n")}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if err := output.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := writer.Write([]byte("three\n")); err != nil {
		t.Fatalf("console output closed process-owned writer: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if want := "one\ntwo\nthree\n"; string(got) != want {
		t.Fatalf("console bytes = %q, want %q", got, want)
	}
}

func TestFileOutputFlushesAcceptedBatchOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.jsonl")
	output, err := corelog.NewFileOutput(path, 4096)
	if err != nil {
		t.Fatalf("NewFileOutput: %v", err)
	}
	if err := output.WriteBatch([][]byte{[]byte("{\"id\":1}\n"), []byte("{\"id\":2}\n")}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"id\":1}\n{\"id\":2}\n"; string(contents) != want {
		t.Fatalf("file bytes = %q, want %q", contents, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if permissions := info.Mode().Perm(); permissions != 0o600 {
			t.Fatalf("new log permissions = %04o, want 0600", permissions)
		}
	}
}

func TestUnixOutputWritesJSONLinesToRealListener(t *testing.T) {
	socketDirectory := shortSocketDirectory(t)
	path := filepath.Join(socketDirectory, "log.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	received := make(chan []byte, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptError <- err
			return
		}
		defer connection.Close()
		contents, err := io.ReadAll(connection)
		if err != nil {
			acceptError <- err
			return
		}
		received <- contents
	}()

	output, err := corelog.NewUnixOutput(path, time.Second)
	if err != nil {
		t.Fatalf("NewUnixOutput: %v", err)
	}
	if err := output.WriteBatch([][]byte{[]byte("{\"id\":1}\n"), []byte("{\"id\":2}\n")}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if err := output.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-acceptError:
		t.Fatal(err)
	case contents := <-received:
		if want := "{\"id\":1}\n{\"id\":2}\n"; string(contents) != want {
			t.Fatalf("socket bytes = %q, want %q", contents, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Unix log records")
	}
}

func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	temporaryRoot := "/tmp"
	if runtime.GOOS == "windows" {
		temporaryRoot = os.TempDir()
	}
	directory, err := os.MkdirTemp(temporaryRoot, "xray-log-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
