package log

import (
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Kind identifies the stable structured event family.
type Kind uint8

const (
	KindUnknown Kind = iota
	KindGeneral
	KindAccess
	KindDNS
	KindInternal
)

// EventMetadata contains fields shared by every structured event.
type EventMetadata struct {
	Timestamp time.Time
	Severity  Severity
	Component string
	SessionID uint32
}

// AccessFields contains structured proxy access data.
type AccessFields struct {
	Source      string
	Destination string
	Network     string
	Status      AccessStatus
	Inbound     string
	Outbound    string
	Email       string
	Reason      string
}

// DNSFields contains structured DNS query data.
type DNSFields struct {
	Server  string
	Domain  string
	Answers []string
	Status  string
	Elapsed time.Duration
	Error   string
}

// Event is an immutable structured log record. Event values can be copied and
// encoded concurrently. Constructors take ownership snapshots of mutable
// inputs before returning.
type Event struct {
	metadata  EventMetadata
	kind      Kind
	message   string
	access    AccessFields
	dns       DNSFields
	truncated bool
}

// NewGeneralEvent creates a structured general log event.
func NewGeneralEvent(metadata EventMetadata, message string) Event {
	return Event{metadata: metadata, kind: KindGeneral, message: message}
}

// NewInternalEvent creates a logger-internal diagnostic event. It is used for
// pipeline health rather than application errors.
func NewInternalEvent(metadata EventMetadata, message string) Event {
	return Event{metadata: metadata, kind: KindInternal, message: message}
}

// NewAccessEvent creates a structured access log event.
func NewAccessEvent(metadata EventMetadata, fields AccessFields) Event {
	return Event{metadata: metadata, kind: KindAccess, access: fields}
}

// NewDNSEvent creates a structured DNS log event and snapshots its answers.
func NewDNSEvent(metadata EventMetadata, fields DNSFields) Event {
	if len(fields.Answers) > 0 {
		fields.Answers = append([]string(nil), fields.Answers...)
	}
	return Event{metadata: metadata, kind: KindDNS, dns: fields}
}

// Kind returns the event family.
func (e Event) Kind() Kind { return e.kind }

// Severity returns the event severity.
func (e Event) Severity() Severity { return e.metadata.Severity }

func (e Event) hasTimestamp() bool { return !e.metadata.Timestamp.IsZero() }

func (e Event) withTimestamp(timestamp time.Time) Event {
	e.metadata.Timestamp = timestamp
	return e
}

// MaskAddresses returns an event copy with typed address fields masked. It
// does not rewrite serialized JSON or arbitrary message text.
func (e Event) MaskAddresses(mask4, mask6 int) Event {
	e.access.Source = maskEndpoint(e.access.Source, mask4, mask6)
	e.access.Destination = maskEndpoint(e.access.Destination, mask4, mask6)
	e.dns.Server = maskEndpoint(e.dns.Server, mask4, mask6)
	if len(e.dns.Answers) > 0 {
		answers := make([]string, len(e.dns.Answers))
		for index, answer := range e.dns.Answers {
			answers[index] = maskEndpoint(answer, mask4, mask6)
		}
		e.dns.Answers = answers
	}
	return e
}

func maskEndpoint(value string, mask4, mask6 int) string {
	if value == "" {
		return ""
	}
	prefix := ""
	endpoint := value
	if strings.HasPrefix(endpoint, "tcp:") || strings.HasPrefix(endpoint, "udp:") {
		prefix = endpoint[:4]
		endpoint = endpoint[4:]
	}
	if host, port, err := net.SplitHostPort(endpoint); err == nil {
		if masked, ok := maskIPAddress(strings.Trim(host, "[]"), mask4, mask6); ok {
			return prefix + net.JoinHostPort(masked, port)
		}
		return value
	}
	if masked, ok := maskIPAddress(strings.Trim(endpoint, "[]"), mask4, mask6); ok {
		return prefix + masked
	}
	return value
}

func maskIPAddress(value string, mask4, mask6 int) (string, bool) {
	ip := net.ParseIP(value)
	if ip == nil {
		return "", false
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		if mask4 >= 32 {
			return value, true
		}
		if mask4 <= 0 {
			return "Masked IPv4", true
		}
		parts := strings.Split(ipv4.String(), ".")
		for index := mask4 / 8; index < len(parts); index++ {
			parts[index] = "*"
		}
		return strings.Join(parts, "."), true
	}
	if mask6 >= 128 {
		return value, true
	}
	if mask6 <= 0 {
		return "Masked IPv6", true
	}
	return ip.Mask(net.CIDRMask(mask6, 128)).String() + "/" + strconv.Itoa(mask6), true
}

func (e Event) bounded(maximumRecordSize int) Event {
	if maximumRecordSize <= 0 {
		return e
	}
	stringBudget := maximumRecordSize - 512
	if stringBudget < 0 {
		stringBudget = 0
	}
	stringBudget /= 6

	e.metadata.Component = boundedEventString(e.metadata.Component, &stringBudget, &e.truncated)
	e.message = boundedEventString(e.message, &stringBudget, &e.truncated)
	e.access.Source = boundedEventString(e.access.Source, &stringBudget, &e.truncated)
	e.access.Destination = boundedEventString(e.access.Destination, &stringBudget, &e.truncated)
	e.access.Network = boundedEventString(e.access.Network, &stringBudget, &e.truncated)
	e.access.Inbound = boundedEventString(e.access.Inbound, &stringBudget, &e.truncated)
	e.access.Outbound = boundedEventString(e.access.Outbound, &stringBudget, &e.truncated)
	e.access.Email = boundedEventString(e.access.Email, &stringBudget, &e.truncated)
	e.access.Reason = boundedEventString(e.access.Reason, &stringBudget, &e.truncated)
	e.dns.Server = boundedEventString(e.dns.Server, &stringBudget, &e.truncated)
	e.dns.Domain = boundedEventString(e.dns.Domain, &stringBudget, &e.truncated)
	e.dns.Status = boundedEventString(e.dns.Status, &stringBudget, &e.truncated)
	e.dns.Error = boundedEventString(e.dns.Error, &stringBudget, &e.truncated)
	if len(e.dns.Answers) > 0 {
		answers := make([]string, 0, min(len(e.dns.Answers), 128))
		for index, answer := range e.dns.Answers {
			if index == 128 || stringBudget == 0 {
				e.truncated = true
				break
			}
			answers = append(answers, boundedEventString(answer, &stringBudget, &e.truncated))
		}
		e.dns.Answers = answers
	}
	return e
}

func boundedEventString(value string, budget *int, truncated *bool) string {
	if value == "" {
		return ""
	}
	if len(value) <= *budget {
		*budget -= len(value)
		return value
	}
	*truncated = true
	if *budget <= 0 {
		return ""
	}
	end := *budget
	for end > 0 && end < len(value) && !utf8.RuneStart(value[end]) {
		end--
	}
	*budget = 0
	return strings.Clone(value[:end])
}
