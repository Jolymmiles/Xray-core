package log

import (
	"strconv"
	"time"
	"unicode/utf8"
)

const jsonSchemaVersion = 1

// Encoder appends one complete encoded event to dst.
type Encoder interface {
	Append(dst []byte, event Event) []byte
}

// JSONEncoder encodes structured events as deterministic JSON Lines. Its zero
// value is ready for concurrent use.
type JSONEncoder struct{}

// Append appends exactly one JSON object and one trailing newline to dst.
func (JSONEncoder) Append(dst []byte, event Event) []byte {
	dst = append(dst, `{"schema":`...)
	dst = strconv.AppendInt(dst, jsonSchemaVersion, 10)
	dst = append(dst, `,"timestamp":`...)
	dst = append(dst, '"')
	dst = event.metadata.Timestamp.UTC().AppendFormat(dst, time.RFC3339Nano)
	dst = append(dst, '"')
	dst = append(dst, `,"type":`...)
	dst = appendJSONString(dst, event.kind.String())
	dst = append(dst, `,"level":`...)
	dst = appendJSONString(dst, severityName(event.metadata.Severity))

	if event.metadata.Component != "" {
		dst = appendJSONField(dst, "component", event.metadata.Component)
	}
	if event.metadata.SessionID != 0 {
		dst = append(dst, `,"session_id":`...)
		dst = strconv.AppendUint(dst, uint64(event.metadata.SessionID), 10)
	}

	switch event.kind {
	case KindGeneral, KindInternal:
		if event.message != "" {
			dst = appendJSONField(dst, "message", event.message)
		}
	case KindAccess:
		dst = appendAccessJSON(dst, event.access)
	case KindDNS:
		dst = appendDNSJSON(dst, event.dns)
	}
	if event.truncated {
		dst = append(dst, `,"truncated":true`...)
	}

	dst = append(dst, '}', '\n')
	return dst
}

func appendAccessJSON(dst []byte, fields AccessFields) []byte {
	if fields.Source != "" {
		dst = appendJSONField(dst, "source", fields.Source)
	}
	if fields.Destination != "" {
		dst = appendJSONField(dst, "destination", fields.Destination)
	}
	if fields.Network != "" {
		dst = appendJSONField(dst, "network", fields.Network)
	}
	if fields.Status != "" {
		dst = appendJSONField(dst, "status", string(fields.Status))
	}
	if fields.Inbound != "" {
		dst = appendJSONField(dst, "inbound", fields.Inbound)
	}
	if fields.Outbound != "" {
		dst = appendJSONField(dst, "outbound", fields.Outbound)
	}
	if fields.Email != "" {
		dst = appendJSONField(dst, "email", fields.Email)
	}
	if fields.Reason != "" {
		dst = appendJSONField(dst, "reason", fields.Reason)
	}
	return dst
}

func appendDNSJSON(dst []byte, fields DNSFields) []byte {
	if fields.Server != "" {
		dst = appendJSONField(dst, "server", fields.Server)
	}
	if fields.Domain != "" {
		dst = appendJSONField(dst, "domain", fields.Domain)
	}
	if len(fields.Answers) > 0 {
		dst = append(dst, `,"answers":[`...)
		for index, answer := range fields.Answers {
			if index > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, answer)
		}
		dst = append(dst, ']')
	}
	if fields.Status != "" {
		dst = appendJSONField(dst, "status", fields.Status)
	}
	if fields.Elapsed > 0 {
		dst = append(dst, `,"elapsed_ms":`...)
		dst = strconv.AppendInt(dst, fields.Elapsed.Milliseconds(), 10)
	}
	if fields.Error != "" {
		dst = appendJSONField(dst, "error", fields.Error)
	}
	return dst
}

func appendJSONField(dst []byte, key, value string) []byte {
	dst = append(dst, ',')
	dst = appendJSONString(dst, key)
	dst = append(dst, ':')
	return appendJSONString(dst, value)
}

func appendJSONString(dst []byte, value string) []byte {
	dst = append(dst, '"')
	segmentStart := 0
	for index := 0; index < len(value); {
		character := value[index]
		if character < utf8.RuneSelf {
			if character >= 0x20 && character != '"' && character != '\\' {
				index++
				continue
			}
			dst = append(dst, value[segmentStart:index]...)
			switch character {
			case '"', '\\':
				dst = append(dst, '\\', character)
			case '\b':
				dst = append(dst, `\b`...)
			case '\f':
				dst = append(dst, `\f`...)
			case '\n':
				dst = append(dst, `\n`...)
			case '\r':
				dst = append(dst, `\r`...)
			case '\t':
				dst = append(dst, `\t`...)
			default:
				dst = append(dst, `\u00`...)
				dst = append(dst, lowerHex[character>>4], lowerHex[character&0x0f])
			}
			index++
			segmentStart = index
			continue
		}

		_, size := utf8.DecodeRuneInString(value[index:])
		if size == 1 {
			dst = append(dst, value[segmentStart:index]...)
			dst = append(dst, `\ufffd`...)
			index++
			segmentStart = index
			continue
		}
		index += size
	}
	dst = append(dst, value[segmentStart:]...)
	dst = append(dst, '"')
	return dst
}

func (kind Kind) String() string {
	switch kind {
	case KindGeneral:
		return "general"
	case KindAccess:
		return "access"
	case KindDNS:
		return "dns"
	case KindInternal:
		return "internal"
	default:
		return "unknown"
	}
}

func severityName(severity Severity) string {
	switch severity {
	case Severity_Error:
		return "error"
	case Severity_Warning:
		return "warning"
	case Severity_Info:
		return "info"
	case Severity_Debug:
		return "debug"
	default:
		return "unknown"
	}
}

const lowerHex = "0123456789abcdef"
