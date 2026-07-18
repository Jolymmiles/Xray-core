package log_test

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
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
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("new log permissions = %04o, want 0600", permissions)
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

func TestUnixOutputReconnectsOnBatchAfterBrokenConnection(t *testing.T) {
	socketDirectory := shortSocketDirectory(t)
	path := filepath.Join(socketDirectory, "reconnect.sock")
	firstListener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}

	collectorStoppedReading := make(chan struct{})
	firstCollectorError := make(chan error, 1)
	go func() {
		connection, err := firstListener.Accept()
		if err != nil {
			firstCollectorError <- err
			return
		}
		if _, err := bufio.NewReader(connection).ReadString('\n'); err != nil {
			_ = connection.Close()
			firstCollectorError <- err
			return
		}
		if err := connection.Close(); err != nil {
			firstCollectorError <- err
			return
		}
		close(collectorStoppedReading)
	}()

	output, err := corelog.NewUnixOutput(path, time.Second)
	if err != nil {
		t.Fatalf("NewUnixOutput: %v", err)
	}
	if err := output.WriteBatch([][]byte{[]byte("{\"id\":1}\n")}); err != nil {
		t.Fatalf("first WriteBatch: %v", err)
	}
	select {
	case err := <-firstCollectorError:
		t.Fatal(err)
	case <-collectorStoppedReading:
	case <-time.After(3 * time.Second):
		t.Fatal("first collector did not stop reading")
	}
	failedBatch := make([]byte, 4*1024*1024)
	failedBatch[len(failedBatch)-1] = '\n'
	if err := output.WriteBatch([][]byte{failedBatch}); err == nil {
		t.Fatal("write to a collector that shut down reads unexpectedly succeeded")
	}

	if err := firstListener.Close(); err != nil {
		t.Fatal(err)
	}
	secondListener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondListener.Close()

	received := make(chan string, 1)
	secondCollectorError := make(chan error, 1)
	go func() {
		connection, err := secondListener.Accept()
		if err != nil {
			secondCollectorError <- err
			return
		}
		defer connection.Close()
		record, err := bufio.NewReader(connection).ReadString('\n')
		if err != nil {
			secondCollectorError <- err
			return
		}
		received <- record
	}()

	if err := output.WriteBatch([][]byte{[]byte("{\"id\":3}\n")}); err != nil {
		t.Fatalf("reconnected WriteBatch: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-secondCollectorError:
		t.Fatal(err)
	case record := <-received:
		if want := "{\"id\":3}\n"; record != want {
			t.Fatalf("reconnected record = %q, want %q", record, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for reconnected record")
	}
	if reconnects := output.Reconnects(); reconnects != 1 {
		t.Fatalf("reconnects = %d, want 1", reconnects)
	}
}

func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "xray-log-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
