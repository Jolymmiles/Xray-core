package log

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/serial"
)

type logKey int

const (
	accessMessageKey logKey = iota
)

type AccessStatus string

const (
	AccessAccepted = AccessStatus("accepted")
	AccessRejected = AccessStatus("rejected")
)

type AccessMessage struct {
	From       interface{}
	To         interface{}
	FromString string
	ToString   string
	Status     AccessStatus
	Reason     interface{}
	Email      string
	Detour     string
}

type accessMessageCarrier interface {
	SetAccessMessage(*AccessMessage)
	GetAccessMessage() *AccessMessage
}

func (m *AccessMessage) String() string {
	from := m.FromString
	if from == "" {
		from = accessValueString(m.From)
	}
	to := m.ToString
	if to == "" {
		to = accessValueString(m.To)
	}
	var reason string
	if m.Reason != nil {
		reason = accessValueString(m.Reason)
	}
	capacity := len("from ") + len(from) + 1 + len(m.Status) + 1 + len(to)
	if len(m.Detour) > 0 {
		capacity += len(" [") + len(m.Detour) + len("]")
	}
	if len(reason) > 0 {
		capacity += 1 + len(reason)
	}
	if len(m.Email) > 0 {
		capacity += len(" email: ") + len(m.Email)
	}
	builder := strings.Builder{}
	builder.Grow(capacity)
	builder.WriteString("from ")
	builder.WriteString(from)
	switch m.Status {
	case AccessAccepted:
		builder.WriteString(" accepted ")
	case AccessRejected:
		builder.WriteString(" rejected ")
	default:
		builder.WriteByte(' ')
		builder.WriteString(string(m.Status))
		builder.WriteByte(' ')
	}
	builder.WriteString(to)

	if len(m.Detour) > 0 {
		builder.WriteString(" [")
		builder.WriteString(m.Detour)
		builder.WriteByte(']')
	}

	if len(reason) > 0 {
		builder.WriteString(" ")
		builder.WriteString(reason)
	}

	if len(m.Email) > 0 {
		builder.WriteString(" email: ")
		builder.WriteString(m.Email)
	}

	return builder.String()
}

func accessValueString(value any) string {
	switch value := value.(type) {
	case nil:
		return ""
	case string:
		return value
	default:
		return serial.ToString(value)
	}
}

func ContextWithAccessMessage(ctx context.Context, accessMessage *AccessMessage) context.Context {
	if carrier, ok := ctx.(accessMessageCarrier); ok {
		carrier.SetAccessMessage(accessMessage)
		return ctx
	}
	return context.WithValue(ctx, accessMessageKey, accessMessage)
}

func AccessMessageFromContext(ctx context.Context) *AccessMessage {
	if carrier, ok := ctx.(accessMessageCarrier); ok {
		return carrier.GetAccessMessage()
	}
	if accessMessage, ok := ctx.Value(accessMessageKey).(*AccessMessage); ok {
		return accessMessage
	}
	return nil
}

// IsAccessMessageKey allows optimized context implementations to preserve
// access-message lookup through later context wrappers.
func IsAccessMessageKey(key any) bool { return key == accessMessageKey }
