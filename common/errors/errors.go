// Package errors is a drop-in replacement for Golang lib 'errors'.
package errors // import "github.com/xtls/xray-core/common/errors"

import (
	"context"
	"runtime"
	"strings"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
)

const trim = len("github.com/xtls/xray-core/")

type hasInnerError interface {
	// Unwrap returns the underlying error of this one.
	Unwrap() error
}

// Error is an error object with underlying error.
type Error struct {
	prefix  []interface{}
	message []interface{}
	caller  string
	inner   error
}

// Error implements error.Error().
func (err *Error) Error() string {
	partCount := len(err.prefix) + len(err.message)
	var inline [8]string
	parts := inline[:0]
	if partCount > len(inline) {
		parts = make([]string, 0, partCount)
	}
	capacity := 0
	for _, prefix := range err.prefix {
		part := serial.ToString(prefix)
		parts = append(parts, part)
		capacity += len(part) + len("[] ")
	}
	if len(err.caller) > 0 {
		capacity += len(err.caller) + len(": ")
	}
	for _, message := range err.message {
		part := serial.ToString(message)
		parts = append(parts, part)
		capacity += len(part)
	}
	inner := ""
	if err.inner != nil {
		inner = err.inner.Error()
		capacity += len(" > ") + len(inner)
	}

	builder := strings.Builder{}
	builder.Grow(capacity)
	for _, prefix := range parts[:len(err.prefix)] {
		builder.WriteByte('[')
		builder.WriteString(prefix)
		builder.WriteString("] ")
	}

	if len(err.caller) > 0 {
		builder.WriteString(err.caller)
		builder.WriteString(": ")
	}

	for _, message := range parts[len(err.prefix):] {
		builder.WriteString(message)
	}

	if err.inner != nil {
		builder.WriteString(" > ")
		builder.WriteString(inner)
	}

	return builder.String()
}

// Unwrap implements hasInnerError.Unwrap()
func (err *Error) Unwrap() error {
	if err.inner == nil {
		return nil
	}
	return err.inner
}

func (err *Error) Base(e error) *Error {
	err.inner = e
	return err
}

// LogComponent returns the stable package name captured when the error was
// created. Structured log adapters use it without parsing the rendered error.
func (err *Error) LogComponent() string {
	return err.caller
}

// String returns the string representation of this error.
func (err *Error) String() string {
	return err.Error()
}

type ExportOptionHolder struct {
	SessionID uint32
}

type ExportOption func(*ExportOptionHolder)

// New returns a new error object with message formed from given arguments.
func New(msg ...interface{}) *Error {
	pc, _, _, _ := runtime.Caller(1)
	details := runtime.FuncForPC(pc).Name()
	if len(details) >= trim {
		details = details[trim:]
	}
	i := strings.Index(details, ".")
	if i > 0 {
		details = details[:i]
	}
	return &Error{
		message: msg,
		caller:  details,
	}
}

func LogDebug(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, log.Severity_Debug, msg...)
}

func LogDebugInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, log.Severity_Debug, msg...)
}

func LogInfo(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, log.Severity_Info, msg...)
}

func LogInfoInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, log.Severity_Info, msg...)
}

func LogWarning(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, log.Severity_Warning, msg...)
}

func LogWarningInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, log.Severity_Warning, msg...)
}

func LogError(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, log.Severity_Error, msg...)
}

func LogErrorInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, log.Severity_Error, msg...)
}

func doLog(ctx context.Context, inner error, severity log.Severity, msg ...interface{}) {
	if !log.ShouldLog(severity) {
		return
	}
	message := append([]interface{}(nil), msg...)
	pc, _, _, _ := runtime.Caller(2)
	details := runtime.FuncForPC(pc).Name()
	if len(details) >= trim {
		details = details[trim:]
	}
	i := strings.Index(details, ".")
	if i > 0 {
		details = details[:i]
	}
	err := &Error{
		message: message,
		caller:  details,
		inner:   inner,
	}
	if ctx != nil && ctx != context.Background() {
		id := uint32(c.IDFromContext(ctx))
		if id > 0 {
			err.prefix = append(err.prefix, id)
		}
	}
	log.Record(&log.GeneralMessage{
		Severity: severity,
		Content:  err,
	})
}

// Cause returns the root cause of this error.
func Cause(err error) error {
	if err == nil {
		return nil
	}
L:
	for {
		switch inner := err.(type) {
		case hasInnerError:
			if inner.Unwrap() == nil {
				break L
			}
			err = inner.Unwrap()
		default:
			break L
		}
	}
	return err
}
