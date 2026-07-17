package log // import "github.com/xtls/xray-core/common/log"

import (
	"sync"

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
	return serial.Concat("[", m.Severity, "] ", m.Content)
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
	sync.RWMutex
	Handler
}

func (h *syncHandler) Handle(msg Message) {
	h.RLock()
	defer h.RUnlock()

	if h.Handler != nil {
		h.Handler.Handle(msg)
	}
}

func (h *syncHandler) Enabled(severity Severity) bool {
	h.RLock()
	defer h.RUnlock()

	if h.Handler == nil {
		return false
	}
	if filter, ok := h.Handler.(SeverityFilter); ok {
		return filter.Enabled(severity)
	}
	return true
}

func (h *syncHandler) Set(handler Handler) {
	h.Lock()
	defer h.Unlock()

	h.Handler = handler
}
