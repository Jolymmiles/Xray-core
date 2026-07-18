package conf

import (
	"fmt"
	"strings"

	"github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
)

func DefaultLogConfig() *log.Config {
	return &log.Config{
		AccessLogType: log.LogType_None,
		ErrorLogType:  log.LogType_Console,
		ErrorLogLevel: clog.Severity_Warning,
	}
}

type LogConfig struct {
	AccessLog   string            `json:"access"`
	ErrorLog    string            `json:"error"`
	LogLevel    string            `json:"loglevel"`
	DNSLog      bool              `json:"dnsLog"`
	MaskAddress string            `json:"maskAddress"`
	Outputs     []LogOutputConfig `json:"outputs"`
}

type LogOutputConfig struct {
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Path           string            `json:"path"`
	Stream         string            `json:"stream"`
	Events         []string          `json:"events"`
	Format         string            `json:"format"`
	Color          string            `json:"color"`
	Level          string            `json:"level"`
	QueueSize      uint32            `json:"queueSize"`
	BatchSize      uint32            `json:"batchSize"`
	FlushInterval  duration.Duration `json:"flushInterval"`
	Backpressure   string            `json:"backpressure"`
	BlockTimeout   duration.Duration `json:"blockTimeout"`
	MaxRecordSize  uint32            `json:"maxRecordSize"`
	FileBufferSize uint32            `json:"fileBufferSize"`
	ConnectTimeout duration.Duration `json:"connectTimeout"`
}

func (v *LogConfig) Build() (*log.Config, error) {
	if v == nil {
		return nil, nil
	}
	config := &log.Config{
		ErrorLogType:  log.LogType_Console,
		AccessLogType: log.LogType_Console,
		EnableDnsLog:  v.DNSLog,
	}

	if v.AccessLog == "none" {
		config.AccessLogType = log.LogType_None
	} else if len(v.AccessLog) > 0 {
		config.AccessLogPath = v.AccessLog
		config.AccessLogType = log.LogType_File
	}
	if v.ErrorLog == "none" {
		config.ErrorLogType = log.LogType_None
	} else if len(v.ErrorLog) > 0 {
		config.ErrorLogPath = v.ErrorLog
		config.ErrorLogType = log.LogType_File
	}

	level := strings.ToLower(strings.TrimSpace(v.LogLevel))
	switch level {
	case "debug":
		config.ErrorLogLevel = clog.Severity_Debug
	case "info":
		config.ErrorLogLevel = clog.Severity_Info
	case "error":
		config.ErrorLogLevel = clog.Severity_Error
	case "none":
		config.ErrorLogType = log.LogType_None
		config.AccessLogType = log.LogType_None
	default:
		config.ErrorLogLevel = clog.Severity_Warning
	}
	config.MaskAddress = v.MaskAddress

	if len(v.Outputs) > 0 {
		outputs, err := buildLogOutputs(v.Outputs, config.ErrorLogLevel)
		if err != nil {
			return nil, err
		}
		config.Outputs = outputs
	}
	return config, nil
}

func buildLogOutputs(source []LogOutputConfig, defaultLevel clog.Severity) ([]*log.OutputConfig, error) {
	outputs := make([]*log.OutputConfig, 0, len(source))
	names := make(map[string]struct{}, len(source))
	for index := range source {
		built, err := source[index].build(defaultLevel)
		if err != nil {
			return nil, fmt.Errorf("log output %d: %w", index, err)
		}
		if _, found := names[built.Name]; found {
			return nil, fmt.Errorf("duplicate log output name %q", built.Name)
		}
		names[built.Name] = struct{}{}
		outputs = append(outputs, built)
	}
	return outputs, nil
}

func (v *LogOutputConfig) build(defaultLevel clog.Severity) (*log.OutputConfig, error) {
	name := strings.TrimSpace(v.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	outputType, err := parseLogOutputType(v.Type)
	if err != nil {
		return nil, err
	}
	path := strings.TrimSpace(v.Path)
	if (outputType == log.OutputType_OutputFile || outputType == log.OutputType_OutputUnix) && path == "" {
		return nil, fmt.Errorf("path is required for %s output", strings.ToLower(strings.TrimPrefix(outputType.String(), "Output")))
	}
	format, err := parseLogFormat(v.Format, outputType)
	if err != nil {
		return nil, err
	}
	if (outputType == log.OutputType_OutputFile || outputType == log.OutputType_OutputUnix) && format != log.LogFormat_FormatJSON {
		return nil, fmt.Errorf("%s output requires json format", strings.ToLower(strings.TrimPrefix(outputType.String(), "Output")))
	}
	color, err := parseLogColor(v.Color)
	if err != nil {
		return nil, err
	}
	stream, err := parseConsoleStream(v.Stream)
	if err != nil {
		return nil, err
	}
	events, err := parseLogEvents(v.Events)
	if err != nil {
		return nil, err
	}
	level, err := parseOutputSeverity(v.Level, defaultLevel)
	if err != nil {
		return nil, err
	}
	backpressure, err := parseLogBackpressure(v.Backpressure)
	if err != nil {
		return nil, err
	}
	if v.MaxRecordSize != 0 && (v.MaxRecordSize < 1024 || v.MaxRecordSize > 16*1024*1024) {
		return nil, fmt.Errorf("maxRecordSize must be between 1024 and 16777216")
	}
	if err := clog.ValidateOutputBufferLimits(int(v.QueueSize), int(v.BatchSize), int(v.MaxRecordSize)); err != nil {
		return nil, err
	}
	return &log.OutputConfig{
		Name:           name,
		Type:           outputType,
		Path:           path,
		Stream:         stream,
		Format:         format,
		Color:          color,
		Events:         events,
		Level:          level,
		QueueSize:      v.QueueSize,
		BatchSize:      v.BatchSize,
		FlushInterval:  int64(v.FlushInterval),
		Backpressure:   backpressure,
		BlockTimeout:   int64(v.BlockTimeout),
		MaxRecordSize:  v.MaxRecordSize,
		FileBufferSize: v.FileBufferSize,
		ConnectTimeout: int64(v.ConnectTimeout),
	}, nil
}

func parseLogOutputType(value string) (log.OutputType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "console":
		return log.OutputType_OutputConsole, nil
	case "file":
		return log.OutputType_OutputFile, nil
	case "unix", "socket":
		return log.OutputType_OutputUnix, nil
	default:
		return log.OutputType_OutputUnknown, fmt.Errorf("unknown type %q", value)
	}
}

func parseLogFormat(value string, outputType log.OutputType) (log.LogFormat, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		if outputType == log.OutputType_OutputConsole {
			return log.LogFormat_FormatConsole, nil
		}
		return log.LogFormat_FormatJSON, nil
	case "console", "text":
		return log.LogFormat_FormatConsole, nil
	case "json", "jsonl":
		return log.LogFormat_FormatJSON, nil
	default:
		return log.LogFormat_FormatUnknown, fmt.Errorf("unknown format %q", value)
	}
}

func parseLogColor(value string) (log.ColorMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return log.ColorMode_ColorAuto, nil
	case "always":
		return log.ColorMode_ColorAlways, nil
	case "never":
		return log.ColorMode_ColorNever, nil
	default:
		return log.ColorMode_ColorAuto, fmt.Errorf("unknown color mode %q", value)
	}
}

func parseConsoleStream(value string) (log.ConsoleStream, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "stdout":
		return log.ConsoleStream_StreamStdout, nil
	case "stderr":
		return log.ConsoleStream_StreamStderr, nil
	default:
		return log.ConsoleStream_StreamStdout, fmt.Errorf("unknown console stream %q", value)
	}
}

func parseLogEvents(values []string) ([]log.EventType, error) {
	if len(values) == 0 {
		return []log.EventType{log.EventType_EventGeneral, log.EventType_EventAccess, log.EventType_EventDNS, log.EventType_EventInternal}, nil
	}
	events := make([]log.EventType, 0, len(values))
	seen := make(map[log.EventType]struct{}, len(values))
	for _, value := range values {
		var event log.EventType
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "general", "error":
			event = log.EventType_EventGeneral
		case "access":
			event = log.EventType_EventAccess
		case "dns":
			event = log.EventType_EventDNS
		case "internal":
			event = log.EventType_EventInternal
		default:
			return nil, fmt.Errorf("unknown event %q", value)
		}
		if _, found := seen[event]; found {
			return nil, fmt.Errorf("duplicate event %q", value)
		}
		seen[event] = struct{}{}
		events = append(events, event)
	}
	return events, nil
}

func parseOutputSeverity(value string, defaultLevel clog.Severity) (clog.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return defaultLevel, nil
	case "debug":
		return clog.Severity_Debug, nil
	case "info":
		return clog.Severity_Info, nil
	case "warning", "warn":
		return clog.Severity_Warning, nil
	case "error":
		return clog.Severity_Error, nil
	default:
		return clog.Severity_Unknown, fmt.Errorf("unknown level %q", value)
	}
}

func parseLogBackpressure(value string) (log.Backpressure, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "drop_new", "drop-new":
		return log.Backpressure_BackpressureDropNew, nil
	case "block":
		return log.Backpressure_BackpressureBlock, nil
	case "sync":
		return log.Backpressure_BackpressureSync, nil
	default:
		return log.Backpressure_BackpressureDropNew, fmt.Errorf("unknown backpressure %q", value)
	}
}
