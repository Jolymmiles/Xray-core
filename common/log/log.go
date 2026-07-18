package log // import "github.com/xtls/xray-core/common/log"

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/serial"
)

// Message is the interface for all log messages.
type Message interface {
	String() string
}

// Handler is the interface for log handler.
type Handler interface {
	Handle(msg Message)
}

// SeverityFilter reports whether a handler accepts a general message severity.
type SeverityFilter interface {
	Enabled(severity Severity) bool
}

// GeneralMessage is a general log message that can contain all kind of content.
type GeneralMessage struct {
	Severity Severity
	Content  interface{}
}

// String implements Message.
func (m *GeneralMessage) String() string {
	severity := m.Severity.String()
	content := serial.ToString(m.Content)
	var builder strings.Builder
	builder.Grow(len(severity) + len(content) + len("[] "))
	builder.WriteByte('[')
	builder.WriteString(severity)
	builder.WriteString("] ")
	builder.WriteString(content)
	return builder.String()
}

// Record writes a message into log stream.
func Record(msg Message) {
	logHandler.Handle(msg)
}

// ShouldLog reports whether the current handler accepts a general message severity.
// Handlers without a SeverityFilter keep the historical behavior and accept all severities.
func ShouldLog(severity Severity) bool {
	return logHandler.Enabled(severity)
}

var logHandler syncHandler

// RegisterHandler registers a new handler as current log handler. Previous registered handler will be discarded.
func RegisterHandler(handler Handler) {
	if handler == nil {
		panic("Log handler is nil")
	}
	logHandler.Set(handler)
}

type syncHandler struct {
	sync.Mutex
	snapshot atomic.Pointer[handlerSnapshot]
}

type handlerSnapshot struct {
	handler Handler
	filter  SeverityFilter
}

func (h *syncHandler) Handle(msg Message) {
	snapshot := h.snapshot.Load()
	if snapshot != nil && snapshot.handler != nil {
		snapshot.handler.Handle(msg)
	}
}

func (h *syncHandler) Enabled(severity Severity) bool {
	snapshot := h.snapshot.Load()
	if snapshot == nil || snapshot.handler == nil {
		return false
	}
	if snapshot.filter != nil {
		return snapshot.filter.Enabled(severity)
	}
	return true
}

func (h *syncHandler) Set(handler Handler) {
	h.Lock()
	defer h.Unlock()

	snapshot := &handlerSnapshot{handler: handler}
	if filter, ok := handler.(SeverityFilter); ok {
		snapshot.filter = filter
	}
	h.snapshot.Store(snapshot)
}
