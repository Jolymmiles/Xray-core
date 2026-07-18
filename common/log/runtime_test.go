package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corelog "github.com/xtls/xray-core/common/log"
)

func TestRuntimeWritesAcceptedEventAndFlushesOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.jsonl")
	fileOutput, err := corelog.NewFileOutput(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	fixedTime := time.Date(2026, time.July, 18, 16, 0, 0, 123, time.UTC)
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Clock: func() time.Time { return fixedTime },
		Outputs: []corelog.OutputOptions{{
			Name:          "access-file",
			Output:        fileOutput,
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindAccess),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     8,
			BatchSize:     4,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureDropNew,
		}},
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	runtime.Emit(corelog.NewAccessEvent(corelog.EventMetadata{
		Severity:  corelog.Severity_Info,
		Component: "app/dispatcher",
	}, corelog.AccessFields{
		Source:      "tcp:192.0.2.1:50000",
		Destination: "tcp:example.com:443",
		Network:     "tcp",
		Status:      corelog.AccessAccepted,
		Inbound:     "vless-in",
		Outbound:    "DIRECT",
	}))

	closeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatalf("Close: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"schema\":1,\"timestamp\":\"2026-07-18T16:00:00.000000123Z\",\"type\":\"access\",\"level\":\"info\",\"component\":\"app/dispatcher\",\"source\":\"tcp:192.0.2.1:50000\",\"destination\":\"tcp:example.com:443\",\"network\":\"tcp\",\"status\":\"accepted\",\"inbound\":\"vless-in\",\"outbound\":\"DIRECT\"}\n"
	if string(contents) != want {
		t.Fatalf("runtime file bytes mismatch\n got: %s\nwant: %s", contents, want)
	}
	stats := runtime.Stats()
	if len(stats) != 1 || stats[0].Accepted != 1 || stats[0].Written != 1 || stats[0].Dropped != 0 || stats[0].QueueDepth != 0 {
		t.Fatalf("unexpected runtime stats: %+v", stats)
	}
}

func TestRuntimeHandlerPreservesStructuredAccessMetadata(t *testing.T) {
	var destination bytes.Buffer
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Clock: func() time.Time { return time.Date(2026, time.July, 18, 16, 1, 0, 0, time.UTC) },
		Outputs: []corelog.OutputOptions{{
			Name:          "access",
			Output:        corelog.NewConsoleOutput(&destination),
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindAccess),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     1,
			BatchSize:     1,
			FlushInterval: time.Hour,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := corelog.NewRuntimeHandler(runtime)
	handler.Handle(&corelog.AccessMessage{
		FromString: "tcp:192.0.2.1:50000",
		ToString:   "tcp:example.com:443",
		Status:     corelog.AccessAccepted,
		Inbound:    "vless-in",
		Outbound:   "DIRECT",
		SessionID:  42,
	})
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}

	var record struct {
		Inbound   string `json:"inbound"`
		Outbound  string `json:"outbound"`
		SessionID uint32 `json:"session_id"`
	}
	if err := json.Unmarshal(destination.Bytes(), &record); err != nil {
		t.Fatalf("invalid access JSON: %v; record=%q", err, destination.Bytes())
	}
	if record.Inbound != "vless-in" || record.Outbound != "DIRECT" || record.SessionID != 42 {
		t.Fatalf("structured access metadata = %+v", record)
	}
}

func TestRuntimeHandlerNormalizesDNSStatus(t *testing.T) {
	var destination bytes.Buffer
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Clock: func() time.Time { return time.Date(2026, time.July, 18, 16, 2, 0, 0, time.UTC) },
		Outputs: []corelog.OutputOptions{{
			Name: "dns", Output: corelog.NewConsoleOutput(&destination), Encoder: corelog.JSONEncoder{},
			Kinds: corelog.KindMaskOf(corelog.KindDNS), MaxSeverity: corelog.Severity_Info,
			QueueSize: 1, BatchSize: 1, FlushInterval: time.Hour,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := corelog.NewRuntimeHandler(runtime)
	handler.Handle(&corelog.DNSLog{Server: "local", Domain: "example.com", Status: corelog.DNSQueried})
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	var record struct {
		Component string `json:"component"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(destination.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Component != "app/dns" || record.Status != "queried" {
		t.Fatalf("structured DNS metadata = %+v", record)
	}
}

func TestRuntimeDropNewIsBoundedAndCounted(t *testing.T) {
	output := newGatedOutput()
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Clock: time.Now,
		Outputs: []corelog.OutputOptions{{
			Name:          "blocked",
			Output:        output,
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Debug,
			QueueSize:     1,
			BatchSize:     1,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureDropNew,
		}},
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	event := corelog.NewGeneralEvent(corelog.EventMetadata{Severity: corelog.Severity_Info}, "event")
	runtime.Emit(event)
	select {
	case <-output.writeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not start its first write")
	}
	runtime.Emit(event)
	runtime.Emit(event)

	stats := runtime.Stats()
	if len(stats) != 1 || stats[0].Accepted != 2 || stats[0].Dropped != 1 || stats[0].QueueDepth != 1 {
		t.Fatalf("overflow stats = %+v, want accepted=2 dropped=1 depth=1", stats)
	}

	close(output.releaseWrite)
	closeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatalf("Close: %v", err)
	}
	stats = runtime.Stats()
	if stats[0].Written != 2 || stats[0].QueueDepth != 0 {
		t.Fatalf("drained stats = %+v, want written=2 depth=0", stats)
	}
}

func TestRuntimeEnabledFiltersByKindAndSeverity(t *testing.T) {
	output := newGatedOutput()
	close(output.releaseWrite)
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Outputs: []corelog.OutputOptions{{
			Name:          "warnings",
			Output:        output,
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Warning,
			QueueSize:     1,
			BatchSize:     1,
			FlushInterval: time.Second,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(context.Background())

	if !runtime.Enabled(corelog.KindGeneral, corelog.Severity_Error) {
		t.Fatal("general error should be enabled")
	}
	if runtime.Enabled(corelog.KindGeneral, corelog.Severity_Info) {
		t.Fatal("general info should be filtered")
	}
	if runtime.Enabled(corelog.KindAccess, corelog.Severity_Error) {
		t.Fatal("access event should be filtered by kind")
	}
}

func TestRuntimeRejectsUnsafeBufferBounds(t *testing.T) {
	base := corelog.OutputOptions{
		Name: "bounded", Output: corelog.NewConsoleOutput(io.Discard), Encoder: corelog.JSONEncoder{},
		Kinds: corelog.KindMaskOf(corelog.KindGeneral), MaxSeverity: corelog.Severity_Info,
	}
	for _, test := range []struct {
		name   string
		mutate func(*corelog.OutputOptions)
	}{
		{name: "queue", mutate: func(options *corelog.OutputOptions) { options.QueueSize = 65537 }},
		{name: "batch", mutate: func(options *corelog.OutputOptions) { options.BatchSize = 4097 }},
		{name: "queued payload", mutate: func(options *corelog.OutputOptions) {
			options.QueueSize = 1024
			options.MaxRecordSize = 1024 * 1024
		}},
		{name: "batch payload", mutate: func(options *corelog.OutputOptions) {
			options.BatchSize = 128
			options.MaxRecordSize = 1024 * 1024
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.mutate(&options)
			if _, err := corelog.NewRuntime(corelog.RuntimeOptions{Outputs: []corelog.OutputOptions{options}}); err == nil {
				t.Fatal("NewRuntime accepted unsafe buffer bounds")
			}
		})
	}
}

func TestRuntimeConcurrentEmitAndCloseAccountsForEveryMatchingEvent(t *testing.T) {
	const (
		emitterCount = 8
		eventsPerRun = 2000
	)
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Outputs: []corelog.OutputOptions{{
			Name:          "discard",
			Output:        corelog.NewConsoleOutput(io.Discard),
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     64,
			BatchSize:     16,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureDropNew,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var emitters sync.WaitGroup
	for range emitterCount {
		emitters.Add(1)
		go func() {
			defer emitters.Done()
			<-start
			event := corelog.NewGeneralEvent(corelog.EventMetadata{
				Timestamp: time.Date(2026, time.July, 18, 16, 1, 0, 0, time.UTC),
				Severity:  corelog.Severity_Info,
			}, "event")
			for range eventsPerRun {
				runtime.Emit(event)
			}
		}()
	}
	close(start)

	closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	closeError := make(chan error, 1)
	go func() { closeError <- runtime.Close(closeContext) }()
	emitters.Wait()
	if err := <-closeError; err != nil {
		t.Fatalf("Close: %v", err)
	}

	stats := runtime.Stats()
	if len(stats) != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	wantTotal := uint64(emitterCount * eventsPerRun)
	if gotTotal := stats[0].Accepted + stats[0].Dropped; gotTotal != wantTotal {
		t.Fatalf("accounted events = %d, want %d; stats=%+v", gotTotal, wantTotal, stats[0])
	}
	if stats[0].Written != stats[0].Accepted {
		t.Fatalf("written=%d accepted=%d; accepted events were not drained", stats[0].Written, stats[0].Accepted)
	}
}

func TestRuntimeReportsDroppedEventsWithoutRecursiveLogging(t *testing.T) {
	output := newGatedOutput()
	var emergency bytes.Buffer
	now := time.Date(2026, time.July, 18, 16, 3, 0, 0, time.UTC)
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Clock:             func() time.Time { return now },
		Emergency:         &emergency,
		EmergencyInterval: time.Minute,
		Outputs: []corelog.OutputOptions{{
			Name:          "blocked",
			Output:        output,
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     1,
			BatchSize:     1,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureDropNew,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := corelog.NewGeneralEvent(corelog.EventMetadata{Severity: corelog.Severity_Info}, "event")
	runtime.Emit(event)
	select {
	case <-output.writeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not enter the gated output")
	}
	runtime.Emit(event)
	runtime.Emit(event)
	runtime.Emit(event)
	if got, want := emergency.String(), "2026-07-18T16:03:00.000Z ERROR internal common/log output=blocked event=dropped count=1\n"; got != want {
		t.Fatalf("rate-limited emergency output = %q, want %q", got, want)
	}

	now = now.Add(time.Minute)
	runtime.Emit(event)
	if got, want := emergency.String(), "2026-07-18T16:03:00.000Z ERROR internal common/log output=blocked event=dropped count=1\n2026-07-18T16:04:00.000Z ERROR internal common/log output=blocked event=dropped count=3\n"; got != want {
		t.Fatalf("emergency output after interval = %q, want %q", got, want)
	}

	close(output.releaseWrite)
	closeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeReportsOutputWriteErrors(t *testing.T) {
	var emergency bytes.Buffer
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Clock:             func() time.Time { return time.Date(2026, time.July, 18, 16, 5, 0, 0, time.UTC) },
		Emergency:         &emergency,
		EmergencyInterval: time.Minute,
		Outputs: []corelog.OutputOptions{{
			Name:          "broken-file",
			Output:        errorOutput{err: errors.New("disk unavailable")},
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     1,
			BatchSize:     1,
			FlushInterval: time.Hour,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime.Emit(corelog.NewGeneralEvent(corelog.EventMetadata{Severity: corelog.Severity_Info}, "event"))
	closeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatal(err)
	}

	stats := runtime.Stats()
	if len(stats) != 1 || stats[0].Accepted != 1 || stats[0].Written != 0 || stats[0].WriteErrors != 1 {
		t.Fatalf("write-error stats = %+v", stats)
	}
	if got, want := emergency.String(), "2026-07-18T16:05:00.000Z ERROR internal common/log output=broken-file event=write_error count=1\n"; got != want {
		t.Fatalf("write-error emergency output = %q, want %q", got, want)
	}
}

func TestRuntimeSyncBackpressureReturnsOnlyAfterWriteCompletes(t *testing.T) {
	output := newGatedOutput()
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Emergency: io.Discard,
		Outputs: []corelog.OutputOptions{{
			Name:          "audit",
			Output:        output,
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     1,
			BatchSize:     1,
			FlushInterval: time.Hour,
			Backpressure:  corelog.BackpressureSync,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 16, 6, 0, 0, time.UTC),
		Severity:  corelog.Severity_Info,
	}, "audit")
	emitDone := make(chan struct{})
	go func() {
		runtime.Emit(event)
		close(emitDone)
	}()
	select {
	case <-output.writeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("sync output write did not start")
	}
	select {
	case <-emitDone:
		t.Fatal("sync Emit returned before WriteBatch completed")
	default:
	}
	stats := runtime.Stats()
	if len(stats) != 1 || stats[0].Accepted != 1 || stats[0].Written != 0 || stats[0].QueueDepth != 0 {
		t.Fatalf("in-flight sync stats = %+v", stats)
	}

	close(output.releaseWrite)
	select {
	case <-emitDone:
	case <-time.After(3 * time.Second):
		t.Fatal("sync Emit did not return after WriteBatch completed")
	}
	stats = runtime.Stats()
	if stats[0].Written != 1 || stats[0].Dropped != 0 || stats[0].WriteErrors != 0 {
		t.Fatalf("completed sync stats = %+v", stats)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeBoundsOversizedEncodedRecord(t *testing.T) {
	const maximumRecordSize = 1024
	path := filepath.Join(t.TempDir(), "bounded.jsonl")
	fileOutput, err := corelog.NewFileOutput(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Emergency: io.Discard,
		Outputs: []corelog.OutputOptions{{
			Name:          "bounded",
			Output:        fileOutput,
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     1,
			BatchSize:     1,
			FlushInterval: time.Hour,
			MaxRecordSize: maximumRecordSize,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	message := "prefix-" + strings.Repeat("\x1b", 1024*1024)
	runtime.Emit(corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 16, 7, 0, 0, time.UTC),
		Severity:  corelog.Severity_Info,
	}, message))
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	record, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(record) > maximumRecordSize {
		t.Fatalf("encoded record size = %d, want at most %d", len(record), maximumRecordSize)
	}
	var decoded struct {
		Message   string `json:"message"`
		Truncated bool   `json:"truncated"`
	}
	if err := json.Unmarshal(record, &decoded); err != nil {
		t.Fatalf("bounded record is not valid JSON: %v\nrecord=%q", err, record)
	}
	if !decoded.Truncated {
		t.Fatal("bounded record does not report truncation")
	}
	if !strings.HasPrefix(decoded.Message, "prefix-") || len(decoded.Message) >= len(message) {
		t.Fatalf("bounded message was not truncated correctly: len=%d", len(decoded.Message))
	}
}

func TestRuntimeReportsFinalFlushError(t *testing.T) {
	var emergency bytes.Buffer
	runtime, err := corelog.NewRuntime(corelog.RuntimeOptions{
		Clock:     func() time.Time { return time.Date(2026, time.July, 18, 16, 8, 0, 0, time.UTC) },
		Emergency: &emergency,
		Outputs: []corelog.OutputOptions{{
			Name:          "flush-error",
			Output:        flushErrorOutput{err: errors.New("flush unavailable")},
			Encoder:       corelog.JSONEncoder{},
			Kinds:         corelog.KindMaskOf(corelog.KindGeneral),
			MaxSeverity:   corelog.Severity_Info,
			QueueSize:     1,
			BatchSize:     1,
			FlushInterval: time.Hour,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(context.Background()); err == nil {
		t.Fatal("final flush error was not returned")
	}
	stats := runtime.Stats()
	if len(stats) != 1 || stats[0].WriteErrors != 1 {
		t.Fatalf("final flush stats = %+v", stats)
	}
	if got, want := emergency.String(), "2026-07-18T16:08:00.000Z ERROR internal common/log output=flush-error event=write_error count=1\n"; got != want {
		t.Fatalf("final flush emergency = %q, want %q", got, want)
	}
}

type gatedOutput struct {
	writeStarted chan struct{}
	releaseWrite chan struct{}
	startOnce    sync.Once
}

func newGatedOutput() *gatedOutput {
	return &gatedOutput{writeStarted: make(chan struct{}), releaseWrite: make(chan struct{})}
}

func (o *gatedOutput) WriteBatch([][]byte) error {
	o.startOnce.Do(func() { close(o.writeStarted) })
	<-o.releaseWrite
	return nil
}

func (*gatedOutput) Flush() error { return nil }
func (*gatedOutput) Close() error { return nil }

type errorOutput struct{ err error }

func (o errorOutput) WriteBatch([][]byte) error { return o.err }
func (errorOutput) Flush() error                { return nil }
func (errorOutput) Close() error                { return nil }

type flushErrorOutput struct{ err error }

func (flushErrorOutput) WriteBatch([][]byte) error { return nil }
func (o flushErrorOutput) Flush() error            { return o.err }
func (flushErrorOutput) Close() error              { return nil }
