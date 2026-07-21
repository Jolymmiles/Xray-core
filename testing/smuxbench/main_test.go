package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
)

func TestRunClientCommand(t *testing.T) {
	listener, stopServer := startTestBenchmarkServer(t)
	defer stopServer()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"client",
		"--target", listener.Addr().String(),
		"--mode", "download",
		"--parallel", "1",
		"--warmup", "0s",
		"--duration", "25ms",
		"--rounds", "1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	var report benchmarkReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Rounds) != 1 || report.Rounds[0].DownloadBytes == 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestRunUsageAndErrors(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		wantCode  int
	}{
		{name: "no command", wantCode: 2},
		{name: "help", arguments: []string{"help"}, wantCode: 0},
		{name: "unknown", arguments: []string{"unknown"}, wantCode: 2},
		{name: "bad client flag", arguments: []string{"client", "--invalid"}, wantCode: 2},
		{name: "bad mode", arguments: []string{"client", "--mode", "invalid"}, wantCode: 2},
		{name: "missing target", arguments: []string{"client"}, wantCode: 1},
		{name: "bad server flag", arguments: []string{"server", "--invalid"}, wantCode: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if got := run(test.arguments, &stdout, &stderr); got != test.wantCode {
				t.Fatalf("exit = %d, want %d; stderr=%s", got, test.wantCode, stderr.String())
			}
		})
	}
}

func TestRunServerCommandStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	output := &notifyWriter{ready: make(chan struct{})}
	go func() {
		<-output.ready
		cancel()
	}()
	var stderr bytes.Buffer
	if code := runServerCommand(ctx, []string{"--listen", "127.0.0.1:0"}, output, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

type notifyWriter struct {
	bytes.Buffer
	once  sync.Once
	ready chan struct{}
}

func (w *notifyWriter) Write(payload []byte) (int, error) {
	written, err := w.Buffer.Write(payload)
	w.once.Do(func() { close(w.ready) })
	return written, err
}
