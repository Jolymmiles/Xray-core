package log_test

import (
	"strings"
	"testing"
	"time"

	corelog "github.com/xtls/xray-core/common/log"
)

func TestConsoleEncoderAppendsDeterministicAccessRecord(t *testing.T) {
	event := consoleAccessEvent()
	encoder := corelog.NewConsoleEncoder(false)

	got := string(encoder.Append(nil, event))
	want := "2026-07-18T15:00:00.123Z INFO  access app/dispatcher session_id=42 source=tcp:192.0.2.10:51000 destination=tcp:100.85.127.181:80 network=tcp status=accepted inbound=\"DE 1 Vless Reality\" outbound=DIRECT email=user@example.com reason=\"route \\\"selected\\\"\"\n"
	if got != want {
		t.Fatalf("console access record mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestConsoleEncoderColorsOnlyTrustedLabels(t *testing.T) {
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 15, 1, 2, 0, time.UTC),
		Severity:  corelog.Severity_Warning,
		Component: "proxy/test",
	}, "untrusted \x1b[31mred\nnext")
	encoder := corelog.NewConsoleEncoder(true)

	got := string(encoder.Append(nil, event))
	want := "2026-07-18T15:01:02.000Z \x1b[33mWARN \x1b[0m \x1b[36mgeneral\x1b[0m proxy/test message=\"untrusted \\u001b[31mred\\nnext\"\n"
	if got != want {
		t.Fatalf("colored console record mismatch\n got: %q\nwant: %q", got, want)
	}
	if strings.Count(got, "\x1b") != 4 {
		t.Fatalf("console record contains an untrusted ANSI sequence: %q", got)
	}
}

func TestConsoleEncoderAllocationBudgetWithCallerCapacity(t *testing.T) {
	event := consoleAccessEvent()
	encoder := corelog.NewConsoleEncoder(false)
	buffer := make([]byte, 0, 512)

	allocations := testing.AllocsPerRun(1000, func() {
		buffer = encoder.Append(buffer[:0], event)
	})
	if allocations != 0 {
		t.Fatalf("console encoding allocations = %.0f, want 0", allocations)
	}
}

func consoleAccessEvent() corelog.Event {
	return corelog.NewAccessEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 15, 0, 0, 123456789, time.UTC),
		Severity:  corelog.Severity_Info,
		Component: "app/dispatcher",
		SessionID: 42,
	}, corelog.AccessFields{
		Source:      "tcp:192.0.2.10:51000",
		Destination: "tcp:100.85.127.181:80",
		Network:     "tcp",
		Status:      corelog.AccessAccepted,
		Inbound:     "DE 1 Vless Reality",
		Outbound:    "DIRECT",
		Email:       "user@example.com",
		Reason:      "route \"selected\"",
	})
}

var consoleEncoderBenchmarkBytes int

func BenchmarkConsoleEncoderAccess(b *testing.B) {
	event := consoleAccessEvent()
	encoder := corelog.NewConsoleEncoder(false)
	buffer := make([]byte, 0, 512)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		buffer = encoder.Append(buffer[:0], event)
	}
	consoleEncoderBenchmarkBytes = len(buffer)
}
