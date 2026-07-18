package log

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	corelog "github.com/xtls/xray-core/common/log"
)

type blockingLifecycleHandler struct {
	handleStarted chan struct{}
	releaseHandle chan struct{}
	closeCalled   chan struct{}
}

func (h *blockingLifecycleHandler) Handle(corelog.Message) {
	close(h.handleStarted)
	<-h.releaseHandle
}

func (h *blockingLifecycleHandler) Close() error {
	close(h.closeCalled)
	return nil
}

func TestFailedStructuredRestartKeepsPreviousRuntimeActive(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.jsonl")
	config := &Config{Outputs: []*OutputConfig{{
		Name:           "events",
		Type:           OutputType_OutputFile,
		Path:           path,
		Format:         LogFormat_FormatJSON,
		Events:         []EventType{EventType_EventGeneral},
		Level:          corelog.Severity_Info,
		QueueSize:      8,
		BatchSize:      2,
		FlushInterval:  int64(time.Hour),
		MaxRecordSize:  65536,
		FileBufferSize: 4096,
	}}}
	logger, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	corelog.Record(&corelog.GeneralMessage{Severity: corelog.Severity_Warning, Content: "before failed restart"})

	config.Outputs[0].Path = filepath.Join(directory, "missing", "events.jsonl")
	if err := logger.Restart(); err == nil {
		t.Fatal("restart with an unavailable file path unexpectedly succeeded")
	}
	corelog.Record(&corelog.GeneralMessage{Severity: corelog.Severity_Warning, Content: "after failed restart"})
	if err := common.Close(logger); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var messages []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		messages = append(messages, record.Message)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"before failed restart", "after failed restart"}
	if len(messages) != len(want) || messages[0] != want[0] || messages[1] != want[1] {
		t.Fatalf("messages after failed restart = %q, want %q", messages, want)
	}
}

func TestStructuredRestartDoesNotCloseHandlerInUse(t *testing.T) {
	oldHandler := &blockingLifecycleHandler{
		handleStarted: make(chan struct{}),
		releaseHandle: make(chan struct{}),
		closeCalled:   make(chan struct{}),
	}
	config := &Config{Outputs: []*OutputConfig{{
		Name: "replacement", Type: OutputType_OutputFile,
		Path: filepath.Join(t.TempDir(), "replacement.jsonl"), Format: LogFormat_FormatJSON,
		Events: []EventType{EventType_EventGeneral}, Level: corelog.Severity_Info,
		QueueSize: 1, BatchSize: 1, FlushInterval: int64(time.Hour), MaxRecordSize: 65536,
	}}}
	logger := &Instance{config: config, structuredLogger: oldHandler, active: true}
	logger.publishState()

	handleDone := make(chan struct{})
	go func() {
		logger.Handle(&corelog.GeneralMessage{Severity: corelog.Severity_Info, Content: "in flight"})
		close(handleDone)
	}()
	<-oldHandler.handleStarted

	restartDone := make(chan error, 1)
	go func() { restartDone <- logger.Restart() }()
	earlyClose := false
	select {
	case <-oldHandler.closeCalled:
		earlyClose = true
	case <-time.After(100 * time.Millisecond):
	}
	close(oldHandler.releaseHandle)
	<-handleDone
	if err := <-restartDone; err != nil {
		t.Fatal(err)
	}
	if !earlyClose {
		select {
		case <-oldHandler.closeCalled:
		case <-time.After(3 * time.Second):
			t.Fatal("old handler was not closed after its in-flight user returned")
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	if earlyClose {
		t.Fatal("restart closed the old handler while Handle was still using it")
	}
}
