package log

import (
	"context"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/serial"
)

const runtimeHandlerCloseTimeout = 5 * time.Second

// RuntimeHandler bridges the historical Message/Handler interface to the
// structured Runtime while call sites are migrated to Event.
type RuntimeHandler struct {
	runtime *Runtime
}

// NewRuntimeHandler creates a compatibility handler for runtime.
func NewRuntimeHandler(runtime *Runtime) *RuntimeHandler {
	return &RuntimeHandler{runtime: runtime}
}

// Handle snapshots a legacy message into a typed structured event.
func (h *RuntimeHandler) Handle(message Message) {
	switch message := message.(type) {
	case *GeneralMessage:
		component := ""
		if provider, ok := message.Content.(interface{ LogComponent() string }); ok {
			component = provider.LogComponent()
		}
		h.runtime.Emit(NewGeneralEvent(EventMetadata{
			Severity:  message.Severity,
			Component: component,
		}, serial.ToString(message.Content)))
	case *AccessMessage:
		destination := message.ToString
		if message.HasTarget {
			destination = message.Target.String()
		} else if destination == "" {
			destination = accessValueString(message.To)
		}
		source := message.FromString
		if source == "" {
			source = accessValueString(message.From)
		}
		reason := ""
		if message.Reason != nil {
			reason = accessValueString(message.Reason)
		}
		outbound := message.Outbound
		if outbound == "" {
			outbound = message.Detour
		}
		h.runtime.Emit(NewAccessEvent(EventMetadata{
			Severity:  Severity_Info,
			Component: message.Component,
			SessionID: message.SessionID,
		}, AccessFields{
			Source:      source,
			Destination: destination,
			Network:     accessNetwork(destination),
			Status:      message.Status,
			Inbound:     message.Inbound,
			Outbound:    outbound,
			Email:       message.Email,
			Reason:      reason,
		}))
	case *DNSLog:
		answers := make([]string, 0, len(message.Result))
		for _, answer := range message.Result {
			answers = append(answers, answer.String())
		}
		errorMessage := ""
		severity := Severity_Info
		if message.Error != nil {
			errorMessage = message.Error.Error()
			severity = Severity_Error
		}
		h.runtime.Emit(NewDNSEvent(EventMetadata{Severity: severity, Component: "app/dns"}, DNSFields{
			Server:  message.Server,
			Domain:  message.Domain,
			Answers: answers,
			Status:  message.Status.structuredName(),
			Elapsed: message.Elapsed,
			Error:   errorMessage,
		}))
	default:
		h.runtime.Emit(NewGeneralEvent(EventMetadata{Severity: Severity_Info}, message.String()))
	}
}

// Enabled implements SeverityFilter.
func (h *RuntimeHandler) Enabled(severity Severity) bool {
	return h.runtime.Enabled(KindGeneral, severity) || h.runtime.Enabled(KindInternal, severity)
}

// Close drains and closes the structured runtime.
func (h *RuntimeHandler) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeHandlerCloseTimeout)
	defer cancel()
	return h.runtime.Close(ctx)
}

// Runtime returns the underlying runtime for operational statistics.
func (h *RuntimeHandler) Runtime() *Runtime { return h.runtime }

func accessNetwork(destination string) string {
	separator := strings.IndexByte(destination, ':')
	if separator <= 0 {
		return ""
	}
	network := destination[:separator]
	if network == "tcp" || network == "udp" {
		return network
	}
	return ""
}
