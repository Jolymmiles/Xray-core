package log

import (
	"bufio"
	"errors"
	"net"
	"testing"
	"time"
)

func TestUnixOutputReconnectsAfterWriteError(t *testing.T) {
	firstOutput, firstCollector := net.Pipe()
	if err := firstCollector.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = firstOutput.Close() })

	secondOutput, secondCollector := net.Pipe()
	t.Cleanup(func() { _ = secondOutput.Close() })
	t.Cleanup(func() { _ = secondCollector.Close() })

	dialCount := 0
	dial := func(string, string, time.Duration) (net.Conn, error) {
		dialCount++
		switch dialCount {
		case 1:
			return firstOutput, nil
		case 2:
			return secondOutput, nil
		default:
			return nil, errors.New("unexpected dial")
		}
	}
	output, err := newUnixOutput("unused", time.Second, dial)
	if err != nil {
		t.Fatalf("newUnixOutput: %v", err)
	}
	t.Cleanup(func() { _ = output.Close() })

	if err := output.WriteBatch([][]byte{[]byte("{\"id\":1}\n")}); err == nil {
		t.Fatal("write to closed collector unexpectedly succeeded")
	}

	received := make(chan string, 1)
	collectorError := make(chan error, 1)
	go func() {
		record, err := bufio.NewReader(secondCollector).ReadString('\n')
		if err != nil {
			collectorError <- err
			return
		}
		received <- record
	}()

	if err := output.WriteBatch([][]byte{[]byte("{\"id\":2}\n")}); err != nil {
		t.Fatalf("reconnected WriteBatch: %v", err)
	}
	select {
	case err := <-collectorError:
		t.Fatal(err)
	case record := <-received:
		if want := "{\"id\":2}\n"; record != want {
			t.Fatalf("reconnected record = %q, want %q", record, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reconnected record")
	}
	if reconnects := output.Reconnects(); reconnects != 1 {
		t.Fatalf("reconnects = %d, want 1", reconnects)
	}
	if dialCount != 2 {
		t.Fatalf("dial count = %d, want 2", dialCount)
	}
}
