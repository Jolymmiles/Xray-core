package log

import (
	"strconv"
)

const consoleTimestampLayout = "2006-01-02T15:04:05.000Z"

// ConsoleEncoder encodes one structured event as a compact human-readable
// line. It is immutable and safe for concurrent use.
type ConsoleEncoder struct {
	color bool
}

// NewConsoleEncoder creates a console encoder. When color is false, the
// encoder never emits ANSI control sequences.
func NewConsoleEncoder(color bool) ConsoleEncoder {
	return ConsoleEncoder{color: color}
}

// Append appends exactly one console record and one trailing newline to dst.
func (e ConsoleEncoder) Append(dst []byte, event Event) []byte {
	dst = event.metadata.Timestamp.UTC().AppendFormat(dst, consoleTimestampLayout)
	dst = append(dst, ' ')
	dst = e.appendLevel(dst, event.metadata.Severity)
	dst = append(dst, ' ')
	dst = e.appendKind(dst, event.kind)
	if event.metadata.Component != "" {
		dst = append(dst, ' ')
		dst = appendConsoleValue(dst, event.metadata.Component)
	}
	if event.metadata.SessionID != 0 {
		dst = append(dst, ` session_id=`...)
		dst = strconv.AppendUint(dst, uint64(event.metadata.SessionID), 10)
	}

	switch event.kind {
	case KindGeneral, KindInternal:
		if event.message != "" {
			dst = append(dst, ` message=`...)
			dst = appendJSONString(dst, event.message)
		}
	case KindAccess:
		dst = appendAccessConsole(dst, event.access)
	case KindDNS:
		dst = appendDNSConsole(dst, event.dns)
	}
	if event.truncated {
		dst = append(dst, ` truncated=true`...)
	}

	return append(dst, '\n')
}

func (e ConsoleEncoder) appendLevel(dst []byte, severity Severity) []byte {
	if e.color {
		dst = append(dst, severityANSI(severity)...)
	}
	dst = append(dst, severityConsoleName(severity)...)
	if e.color {
		dst = append(dst, ansiReset...)
	}
	return dst
}

func (e ConsoleEncoder) appendKind(dst []byte, kind Kind) []byte {
	if e.color {
		dst = append(dst, ansiCyan...)
	}
	dst = append(dst, kind.String()...)
	if e.color {
		dst = append(dst, ansiReset...)
	}
	return dst
}

func appendAccessConsole(dst []byte, fields AccessFields) []byte {
	dst = appendOptionalConsoleField(dst, "source", fields.Source)
	dst = appendOptionalConsoleField(dst, "destination", fields.Destination)
	dst = appendOptionalConsoleField(dst, "network", fields.Network)
	dst = appendOptionalConsoleField(dst, "status", string(fields.Status))
	dst = appendOptionalConsoleField(dst, "inbound", fields.Inbound)
	dst = appendOptionalConsoleField(dst, "outbound", fields.Outbound)
	dst = appendOptionalConsoleField(dst, "email", fields.Email)
	dst = appendOptionalConsoleField(dst, "reason", fields.Reason)
	return dst
}

func appendDNSConsole(dst []byte, fields DNSFields) []byte {
	dst = appendOptionalConsoleField(dst, "server", fields.Server)
	dst = appendOptionalConsoleField(dst, "domain", fields.Domain)
	if len(fields.Answers) > 0 {
		dst = append(dst, ` answers=[`...)
		for index, answer := range fields.Answers {
			if index > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, answer)
		}
		dst = append(dst, ']')
	}
	dst = appendOptionalConsoleField(dst, "status", fields.Status)
	if fields.Elapsed > 0 {
		dst = append(dst, ` elapsed_ms=`...)
		dst = strconv.AppendInt(dst, fields.Elapsed.Milliseconds(), 10)
	}
	dst = appendOptionalConsoleField(dst, "error", fields.Error)
	return dst
}

func appendOptionalConsoleField(dst []byte, key, value string) []byte {
	if value == "" {
		return dst
	}
	dst = append(dst, ' ')
	dst = append(dst, key...)
	dst = append(dst, '=')
	return appendConsoleValue(dst, value)
}

func appendConsoleValue(dst []byte, value string) []byte {
	if isSafeConsoleToken(value) {
		return append(dst, value...)
	}
	return appendJSONString(dst, value)
}

func isSafeConsoleToken(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func severityConsoleName(severity Severity) string {
	switch severity {
	case Severity_Error:
		return "ERROR"
	case Severity_Warning:
		return "WARN "
	case Severity_Info:
		return "INFO "
	case Severity_Debug:
		return "DEBUG"
	default:
		return "UNKWN"
	}
}

func severityANSI(severity Severity) string {
	switch severity {
	case Severity_Error:
		return ansiRed
	case Severity_Warning:
		return ansiYellow
	case Severity_Info:
		return ansiGreen
	case Severity_Debug:
		return ansiGray
	default:
		return ansiGray
	}
}

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
	ansiCyan   = "\x1b[36m"
	ansiGray   = "\x1b[90m"
)
