package conf

import (
	"testing"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	corelog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
)

func TestLogConfigBuildPreservesLegacyFields(t *testing.T) {
	built, err := (&LogConfig{
		AccessLog:   "/var/log/xray/access.log",
		ErrorLog:    "none",
		LogLevel:    "info",
		DNSLog:      true,
		MaskAddress: "half",
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if built.AccessLogType != applog.LogType_File || built.AccessLogPath != "/var/log/xray/access.log" {
		t.Fatalf("legacy access config changed: %+v", built)
	}
	if built.ErrorLogType != applog.LogType_None || built.ErrorLogLevel != corelog.Severity_Info {
		t.Fatalf("legacy error config changed: %+v", built)
	}
	if !built.EnableDnsLog || built.MaskAddress != "half" || len(built.Outputs) != 0 {
		t.Fatalf("legacy auxiliary config changed: %+v", built)
	}
}

func TestLogConfigBuildsExplicitStructuredOutputs(t *testing.T) {
	built, err := (&LogConfig{
		LogLevel: "warning",
		Outputs: []LogOutputConfig{
			{
				Name:          "console",
				Type:          "console",
				Stream:        "stderr",
				Events:        []string{"general", "internal"},
				Format:        "console",
				Color:         "auto",
				QueueSize:     256,
				BatchSize:     16,
				FlushInterval: duration.Duration(250 * time.Millisecond),
				Backpressure:  "drop_new",
				MaxRecordSize: 65536,
			},
			{
				Name:           "collector",
				Type:           "unix",
				Path:           "/run/xray/log.sock",
				Events:         []string{"access", "dns"},
				Format:         "json",
				Level:          "info",
				QueueSize:      4096,
				BatchSize:      64,
				FlushInterval:  duration.Duration(time.Second),
				Backpressure:   "block",
				BlockTimeout:   duration.Duration(50 * time.Millisecond),
				MaxRecordSize:  65536,
				ConnectTimeout: duration.Duration(2 * time.Second),
			},
		},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Outputs) != 2 {
		t.Fatalf("output count = %d, want 2", len(built.Outputs))
	}
	console := built.Outputs[0]
	if console.Name != "console" || console.Type != applog.OutputType_OutputConsole || console.Stream != applog.ConsoleStream_StreamStderr || console.Format != applog.LogFormat_FormatConsole || console.Color != applog.ColorMode_ColorAuto {
		t.Fatalf("console output mismatch: %+v", console)
	}
	if console.Level != corelog.Severity_Warning || console.QueueSize != 256 || console.BatchSize != 16 || console.FlushInterval != int64(250*time.Millisecond) || console.MaxRecordSize != 65536 {
		t.Fatalf("console runtime fields mismatch: %+v", console)
	}
	if len(console.Events) != 2 || console.Events[0] != applog.EventType_EventGeneral || console.Events[1] != applog.EventType_EventInternal {
		t.Fatalf("console events mismatch: %+v", console.Events)
	}
	collector := built.Outputs[1]
	if collector.Type != applog.OutputType_OutputUnix || collector.Path != "/run/xray/log.sock" || collector.Format != applog.LogFormat_FormatJSON || collector.Level != corelog.Severity_Info {
		t.Fatalf("collector output mismatch: %+v", collector)
	}
	if collector.Backpressure != applog.Backpressure_BackpressureBlock || collector.BlockTimeout != int64(50*time.Millisecond) || collector.ConnectTimeout != int64(2*time.Second) {
		t.Fatalf("collector lifecycle fields mismatch: %+v", collector)
	}
}

func TestLogConfigRejectsUnknownStructuredEvent(t *testing.T) {
	_, err := (&LogConfig{Outputs: []LogOutputConfig{{
		Name:   "bad",
		Type:   "console",
		Events: []string{"packet-capture"},
	}}}).Build()
	if err == nil {
		t.Fatal("unknown structured event was accepted")
	}
}

func TestLogConfigRejectsUnsafeStructuredMemoryBudget(t *testing.T) {
	_, err := (&LogConfig{Outputs: []LogOutputConfig{{
		Name: "unsafe", Type: "file", Path: "/tmp/unsafe.jsonl",
		QueueSize: 1024, BatchSize: 128, MaxRecordSize: 1024 * 1024,
	}}}).Build()
	if err == nil {
		t.Fatal("unsafe structured log memory budget was accepted")
	}
}
