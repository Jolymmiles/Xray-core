package log

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
)

type HandlerCreatorOptions struct {
	Path string
}

type HandlerCreator func(LogType, HandlerCreatorOptions) (log.Handler, error)

var handlerCreatorMap = make(map[LogType]HandlerCreator)

var handlerCreatorMapLock = &sync.RWMutex{}

func RegisterHandlerCreator(logType LogType, f HandlerCreator) error {
	if f == nil {
		return errors.New("nil HandlerCreator")
	}

	handlerCreatorMapLock.Lock()
	defer handlerCreatorMapLock.Unlock()

	handlerCreatorMap[logType] = f
	return nil
}

func createHandler(logType LogType, options HandlerCreatorOptions) (log.Handler, error) {
	handlerCreatorMapLock.RLock()
	defer handlerCreatorMapLock.RUnlock()

	creator, found := handlerCreatorMap[logType]
	if !found {
		return nil, errors.New("unable to create log handler for ", logType)
	}
	return creator(logType, options)
}

func createStructuredHandler(configs []*OutputConfig, maskAddresses bool, mask4, mask6 int) (log.Handler, error) {
	if err := validateStructuredConfigs(configs); err != nil {
		return nil, err
	}
	outputOptions := make([]log.OutputOptions, 0, len(configs))
	createdOutputs := make([]log.Output, 0, len(configs))
	closeCreated := func() {
		for _, output := range createdOutputs {
			common.Close(output)
		}
	}
	for index, config := range configs {
		if config == nil {
			closeCreated()
			return nil, errors.New("nil structured log output at index ", index)
		}
		output, err := createStructuredOutput(config)
		if err != nil {
			closeCreated()
			return nil, errors.New("failed to create structured log output ", config.Name).Base(err)
		}
		createdOutputs = append(createdOutputs, output)
		encoder, err := createStructuredEncoder(config, output)
		if err != nil {
			closeCreated()
			return nil, errors.New("failed to create structured log encoder ", config.Name).Base(err)
		}
		if maskAddresses {
			encoder = structuredMaskingEncoder{inner: encoder, mask4: mask4, mask6: mask6}
		}
		outputOptions = append(outputOptions, log.OutputOptions{
			Name:          config.Name,
			Output:        output,
			Encoder:       encoder,
			Kinds:         structuredKindMask(config.Events),
			MaxSeverity:   config.Level,
			QueueSize:     int(config.QueueSize),
			BatchSize:     int(config.BatchSize),
			FlushInterval: time.Duration(config.FlushInterval),
			Backpressure:  structuredBackpressure(config.Backpressure),
			BlockTimeout:  time.Duration(config.BlockTimeout),
			MaxRecordSize: int(config.MaxRecordSize),
		})
	}
	runtime, err := log.NewRuntime(log.RuntimeOptions{Emergency: os.Stderr, Outputs: outputOptions})
	if err != nil {
		closeCreated()
		return nil, err
	}
	return log.NewRuntimeHandler(runtime), nil
}

func validateStructuredConfigs(configs []*OutputConfig) error {
	names := make(map[string]struct{}, len(configs))
	destinations := make(map[string]string, len(configs))
	for index, config := range configs {
		if config == nil {
			return errors.New("nil structured log output at index ", index)
		}
		if strings.TrimSpace(config.Name) == "" {
			return errors.New("structured log output ", index, " has an empty name")
		}
		if _, found := names[config.Name]; found {
			return errors.New("duplicate structured log output name ", config.Name)
		}
		names[config.Name] = struct{}{}
		if config.Type < OutputType_OutputConsole || config.Type > OutputType_OutputUnix {
			return errors.New("structured log output ", config.Name, " has an invalid type")
		}
		if config.Format != LogFormat_FormatConsole && config.Format != LogFormat_FormatJSON {
			return errors.New("structured log output ", config.Name, " has an invalid format")
		}
		if config.Type != OutputType_OutputConsole && config.Format != LogFormat_FormatJSON {
			return errors.New("structured log output ", config.Name, " requires JSON format")
		}
		if config.Color < ColorMode_ColorAuto || config.Color > ColorMode_ColorNever {
			return errors.New("structured log output ", config.Name, " has an invalid color mode")
		}
		if config.Stream < ConsoleStream_StreamStdout || config.Stream > ConsoleStream_StreamStderr {
			return errors.New("structured log output ", config.Name, " has an invalid console stream")
		}
		if config.Level < log.Severity_Unknown || config.Level > log.Severity_Debug {
			return errors.New("structured log output ", config.Name, " has an invalid severity")
		}
		if config.Backpressure < Backpressure_BackpressureDropNew || config.Backpressure > Backpressure_BackpressureSync {
			return errors.New("structured log output ", config.Name, " has an invalid backpressure policy")
		}
		seenEvents := make(map[EventType]struct{}, len(config.Events))
		for _, event := range config.Events {
			if event < EventType_EventGeneral || event > EventType_EventInternal {
				return errors.New("structured log output ", config.Name, " has an invalid event type")
			}
			if _, found := seenEvents[event]; found {
				return errors.New("structured log output ", config.Name, " has a duplicate event type")
			}
			seenEvents[event] = struct{}{}
		}
		if config.FlushInterval < 0 || config.BlockTimeout < 0 || config.ConnectTimeout < 0 {
			return errors.New("structured log output ", config.Name, " has a negative duration")
		}
		if config.FileBufferSize > 16*1024*1024 {
			return errors.New("structured log output ", config.Name, " file buffer exceeds 16777216 bytes")
		}
		if err := log.ValidateOutputBufferLimits(int(config.QueueSize), int(config.BatchSize), int(config.MaxRecordSize)); err != nil {
			return errors.New("structured log output ", config.Name, ": ").Base(err)
		}
		if config.Type == OutputType_OutputFile || config.Type == OutputType_OutputUnix {
			if strings.TrimSpace(config.Path) == "" {
				return errors.New("structured log output ", config.Name, " has an empty path")
			}
			destination := config.Type.String() + ":" + filepath.Clean(config.Path)
			if previous, found := destinations[destination]; found {
				return errors.New("structured log outputs ", previous, " and ", config.Name, " share destination ", config.Path)
			}
			destinations[destination] = config.Name
		}
	}
	return nil
}

type structuredMaskingEncoder struct {
	inner        log.Encoder
	mask4, mask6 int
}

func (e structuredMaskingEncoder) Append(destination []byte, event log.Event) []byte {
	return e.inner.Append(destination, event.MaskAddresses(e.mask4, e.mask6))
}

func createStructuredOutput(config *OutputConfig) (log.Output, error) {
	switch config.Type {
	case OutputType_OutputConsole:
		if config.Stream == ConsoleStream_StreamStderr {
			return log.NewConsoleOutput(os.Stderr), nil
		}
		return log.NewConsoleOutput(os.Stdout), nil
	case OutputType_OutputFile:
		return log.NewFileOutput(config.Path, int(config.FileBufferSize))
	case OutputType_OutputUnix:
		timeout := time.Duration(config.ConnectTimeout)
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		return log.NewUnixOutput(config.Path, timeout)
	default:
		return nil, errors.New("unknown structured output type ", config.Type)
	}
}

func createStructuredEncoder(config *OutputConfig, output log.Output) (log.Encoder, error) {
	switch config.Format {
	case LogFormat_FormatJSON:
		return log.JSONEncoder{}, nil
	case LogFormat_FormatConsole:
		console, ok := output.(*log.ConsoleOutput)
		if !ok {
			return nil, errors.New("console format requires console output")
		}
		return log.NewConsoleEncoder(structuredColorEnabled(config.Color, console)), nil
	default:
		return nil, errors.New("unknown structured log format ", config.Format)
	}
}

func structuredColorEnabled(mode ColorMode, output *log.ConsoleOutput) bool {
	switch mode {
	case ColorMode_ColorAlways:
		return true
	case ColorMode_ColorNever:
		return false
	case ColorMode_ColorAuto:
		if os.Getenv("NO_COLOR") != "" {
			return false
		}
		return output.IsTerminal()
	default:
		return false
	}
}

func structuredKindMask(events []EventType) log.KindMask {
	if len(events) == 0 {
		return 0
	}
	kinds := make([]log.Kind, 0, len(events))
	for _, event := range events {
		switch event {
		case EventType_EventGeneral:
			kinds = append(kinds, log.KindGeneral)
		case EventType_EventAccess:
			kinds = append(kinds, log.KindAccess)
		case EventType_EventDNS:
			kinds = append(kinds, log.KindDNS)
		case EventType_EventInternal:
			kinds = append(kinds, log.KindInternal)
		}
	}
	return log.KindMaskOf(kinds...)
}

func structuredBackpressure(policy Backpressure) log.BackpressurePolicy {
	switch policy {
	case Backpressure_BackpressureBlock:
		return log.BackpressureBlock
	case Backpressure_BackpressureSync:
		return log.BackpressureSync
	default:
		return log.BackpressureDropNew
	}
}

func init() {
	common.Must(RegisterHandlerCreator(LogType_Console, func(lt LogType, options HandlerCreatorOptions) (log.Handler, error) {
		return log.NewLogger(log.CreateStdoutLogWriter()), nil
	}))

	common.Must(RegisterHandlerCreator(LogType_File, func(lt LogType, options HandlerCreatorOptions) (log.Handler, error) {
		creator, err := log.CreateFileLogWriter(options.Path)
		if err != nil {
			return nil, err
		}
		return log.NewLogger(creator), nil
	}))

	common.Must(RegisterHandlerCreator(LogType_None, func(lt LogType, options HandlerCreatorOptions) (log.Handler, error) {
		return nil, nil
	}))
}
