package log_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/common"
	xerrors "github.com/xtls/xray-core/common/errors"
	corelog "github.com/xtls/xray-core/common/log"
)

func TestStructuredFileLoggerBridgesLegacyGeneralAndAccessMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	logger, err := applog.New(context.Background(), &applog.Config{
		ErrorLogType:  applog.LogType_None,
		AccessLogType: applog.LogType_None,
		Outputs: []*applog.OutputConfig{{
			Name:           "events",
			Type:           applog.OutputType_OutputFile,
			Path:           path,
			Format:         applog.LogFormat_FormatJSON,
			Events:         []applog.EventType{applog.EventType_EventGeneral, applog.EventType_EventAccess},
			Level:          corelog.Severity_Info,
			QueueSize:      16,
			BatchSize:      4,
			FlushInterval:  int64(time.Hour),
			Backpressure:   applog.Backpressure_BackpressureDropNew,
			MaxRecordSize:  65536,
			FileBufferSize: 4096,
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	corelog.Record(&corelog.GeneralMessage{Severity: corelog.Severity_Warning, Content: "warning message"})
	corelog.Record(&corelog.AccessMessage{
		FromString: "tcp:192.0.2.1:50000",
		ToString:   "tcp:example.com:443",
		Status:     corelog.AccessAccepted,
		Email:      "user@example.com",
		Detour:     "vless-in -> DIRECT",
	})
	if err := common.Close(logger); err != nil {
		t.Fatalf("Close: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var records []map[string]any
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("invalid JSONL record %q: %v", scanner.Bytes(), err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2; records=%+v", len(records), records)
	}
	if records[0]["type"] != "general" || records[0]["level"] != "warning" || records[0]["message"] != "warning message" {
		t.Fatalf("general record mismatch: %+v", records[0])
	}
	if records[1]["type"] != "access" || records[1]["source"] != "tcp:192.0.2.1:50000" || records[1]["destination"] != "tcp:example.com:443" || records[1]["outbound"] != "vless-in -> DIRECT" {
		t.Fatalf("access record mismatch: %+v", records[1])
	}
}

func TestStructuredLoggerExposesOperationalStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.jsonl")
	logger, err := applog.New(context.Background(), &applog.Config{Outputs: []*applog.OutputConfig{{
		Name:           "stats",
		Type:           applog.OutputType_OutputFile,
		Path:           path,
		Format:         applog.LogFormat_FormatJSON,
		Events:         []applog.EventType{applog.EventType_EventGeneral},
		Level:          corelog.Severity_Info,
		QueueSize:      4,
		BatchSize:      1,
		FlushInterval:  int64(time.Hour),
		MaxRecordSize:  65536,
		FileBufferSize: 4096,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	corelog.Record(&corelog.GeneralMessage{Severity: corelog.Severity_Info, Content: "counted"})
	deadline := time.Now().Add(3 * time.Second)
	for {
		stats := logger.StructuredStats()
		if len(stats) == 1 && stats[0].Written == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("structured stats did not observe write: %+v", stats)
		}
		time.Sleep(time.Millisecond)
	}
	stats := logger.StructuredStats()
	if err := common.Close(logger); err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Name != "stats" || stats[0].Accepted != 1 || stats[0].Written != 1 {
		t.Fatalf("structured stats = %+v", stats)
	}
}

func TestStructuredGeneralErrorIncludesComponent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "component.jsonl")
	logger, err := applog.New(context.Background(), &applog.Config{Outputs: []*applog.OutputConfig{{
		Name: "component", Type: applog.OutputType_OutputFile, Path: path, Format: applog.LogFormat_FormatJSON,
		Events: []applog.EventType{applog.EventType_EventGeneral}, Level: corelog.Severity_Info,
		QueueSize: 1, BatchSize: 1, FlushInterval: int64(time.Hour), MaxRecordSize: 65536,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	corelog.Record(&corelog.GeneralMessage{Severity: corelog.Severity_Info, Content: xerrors.New("structured")})
	if err := common.Close(logger); err != nil {
		t.Fatal(err)
	}
	var record struct {
		Component string `json:"component"`
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, &record); err != nil {
		t.Fatal(err)
	}
	if record.Component != "app/log_test" {
		t.Fatalf("component = %q, want app/log_test", record.Component)
	}
}

func TestStructuredLoggerRejectsDuplicateFileDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "duplicate.jsonl")
	output := func(name string) *applog.OutputConfig {
		return &applog.OutputConfig{
			Name: name, Type: applog.OutputType_OutputFile, Path: path, Format: applog.LogFormat_FormatJSON,
			Events: []applog.EventType{applog.EventType_EventGeneral}, Level: corelog.Severity_Info,
			QueueSize: 1, BatchSize: 1, FlushInterval: int64(time.Hour), MaxRecordSize: 65536,
		}
	}
	logger, err := applog.New(context.Background(), &applog.Config{Outputs: []*applog.OutputConfig{output("first"), output("second")}})
	if logger != nil {
		_ = common.Close(logger)
	}
	if err == nil {
		t.Fatal("duplicate structured file destination was accepted")
	}
}

func TestStructuredFileLoggerMasksTypedAccessAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "masked.jsonl")
	logger, err := applog.New(context.Background(), &applog.Config{
		MaskAddress: "half",
		Outputs: []*applog.OutputConfig{{
			Name:           "masked",
			Type:           applog.OutputType_OutputFile,
			Path:           path,
			Format:         applog.LogFormat_FormatJSON,
			Events:         []applog.EventType{applog.EventType_EventAccess},
			Level:          corelog.Severity_Info,
			QueueSize:      4,
			BatchSize:      1,
			FlushInterval:  int64(time.Hour),
			MaxRecordSize:  65536,
			FileBufferSize: 4096,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	corelog.Record(&corelog.AccessMessage{
		FromString: "tcp:192.0.2.1:50000",
		ToString:   "tcp:203.0.113.4:443",
		Status:     corelog.AccessAccepted,
	})
	if err := common.Close(logger); err != nil {
		t.Fatal(err)
	}

	record, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}
	if err := json.Unmarshal(record, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Source != "tcp:192.0.*.*:50000" || decoded.Destination != "tcp:203.0.*.*:443" {
		t.Fatalf("masked endpoints = (%q, %q)", decoded.Source, decoded.Destination)
	}
}

func TestStructuredUnixLoggerWritesJSONToRealCollector(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "xray-app-log-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "events.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 1)
	collectorError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			collectorError <- err
			return
		}
		defer connection.Close()
		scanner := bufio.NewScanner(connection)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				collectorError <- err
			}
			return
		}
		received <- append([]byte(nil), scanner.Bytes()...)
	}()

	logger, err := applog.New(context.Background(), &applog.Config{Outputs: []*applog.OutputConfig{{
		Name:           "collector",
		Type:           applog.OutputType_OutputUnix,
		Path:           path,
		Format:         applog.LogFormat_FormatJSON,
		Events:         []applog.EventType{applog.EventType_EventGeneral},
		Level:          corelog.Severity_Info,
		QueueSize:      4,
		BatchSize:      1,
		FlushInterval:  int64(time.Hour),
		ConnectTimeout: int64(time.Second),
		MaxRecordSize:  65536,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	corelog.Record(&corelog.GeneralMessage{Severity: corelog.Severity_Info, Content: "socket event"})
	if err := common.Close(logger); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-collectorError:
		t.Fatal(err)
	case record := <-received:
		var decoded struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(record, &decoded); err != nil {
			t.Fatalf("collector received invalid JSON: %v; record=%q", err, record)
		}
		if decoded.Type != "general" || decoded.Message != "socket event" {
			t.Fatalf("collector record = %+v", decoded)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for structured Unix log event")
	}
}
