package log

import (
	"context"
	"strconv"
	"strings"

	commonctx "github.com/xtls/xray-core/common/ctx"
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

type stringAddress interface {
	String() string
}

// AccessTarget stores a routed destination without importing the common/net
// package or formatting it on the dispatcher hot path.
type AccessTarget struct {
	Network string
	Address stringAddress
	Port    uint16
}

func (t AccessTarget) String() string {
	if t.Address == nil {
		return ""
	}
	address := t.Address.String()
	capacity := len(t.Network) + 1 + len(address) + 1 + 5
	var builder strings.Builder
	builder.Grow(capacity)
	if t.Network != "" {
		builder.WriteString(t.Network)
		builder.WriteByte(':')
	}
	builder.WriteString(address)
	if t.Network != "unix" {
		builder.WriteByte(':')
		builder.WriteString(strconv.FormatUint(uint64(t.Port), 10))
	}
	return builder.String()
}

type AccessMessage struct {
	Component  string
	From       interface{}
	To         interface{}
	FromString string
	ToString   string
	Target     AccessTarget
	HasTarget  bool
	Status     AccessStatus
	Reason     interface{}
	Email      string
	Detour     string
	Inbound    string
	Outbound   string
	SessionID  uint32
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
	if m.HasTarget {
		to = m.Target.String()
	} else if to == "" {
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

// RecordAccess stamps context-owned metadata before publishing an access
// record. Callers still provide protocol-specific component and inbound data.
func RecordAccess(ctx context.Context, accessMessage *AccessMessage) {
	if accessMessage.SessionID == 0 {
		accessMessage.SessionID = uint32(commonctx.IDFromContext(ctx))
	}
	Record(accessMessage)
}

func ContextWithAccessMessage(ctx context.Context, accessMessage *AccessMessage) context.Context {
	if accessMessage.SessionID == 0 {
		accessMessage.SessionID = uint32(commonctx.IDFromContext(ctx))
	}
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
