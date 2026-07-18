package log_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	corelog "github.com/xtls/xray-core/common/log"
)

func TestJSONEncoderAppendsDeterministicAccessRecord(t *testing.T) {
	timestamp := time.Date(2026, time.July, 18, 15, 0, 0, 123456789, time.UTC)
	event := corelog.NewAccessEvent(corelog.EventMetadata{
		Timestamp: timestamp,
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

	got := string((corelog.JSONEncoder{}).Append(nil, event))
	want := "{\"schema\":1,\"timestamp\":\"2026-07-18T15:00:00.123456789Z\",\"type\":\"access\",\"level\":\"info\",\"component\":\"app/dispatcher\",\"session_id\":42,\"source\":\"tcp:192.0.2.10:51000\",\"destination\":\"tcp:100.85.127.181:80\",\"network\":\"tcp\",\"status\":\"accepted\",\"inbound\":\"DE 1 Vless Reality\",\"outbound\":\"DIRECT\",\"email\":\"user@example.com\",\"reason\":\"route \\\"selected\\\"\"}\n"
	if got != want {
		t.Fatalf("JSON access record mismatch\n got: %s\nwant: %s", got, want)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("JSON access record is not independently parseable: %v", err)
	}
	if gotSessionID := decoded["session_id"]; gotSessionID != float64(42) {
		t.Fatalf("session_id = %#v, want 42", gotSessionID)
	}
}

func TestJSONEncoderEscapesUntrustedGeneralMessageAsValidJSON(t *testing.T) {
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 15, 1, 2, 0, time.UTC),
		Severity:  corelog.Severity_Warning,
		Component: "proxy/test",
	}, "line one\nline two\t\x1b[31m\xff")

	encoded := (corelog.JSONEncoder{}).Append(nil, event)
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' {
		t.Fatalf("encoded record does not end in one newline: %q", encoded)
	}
	if len(encoded) > 1 && encoded[len(encoded)-2] == '\n' {
		t.Fatalf("encoded record ends in more than one newline: %q", encoded)
	}
	if strings.Contains(string(encoded), "\x1b") {
		t.Fatalf("encoded JSON contains a literal ANSI escape: %q", encoded)
	}

	var decoded struct {
		Schema    int    `json:"schema"`
		Timestamp string `json:"timestamp"`
		Type      string `json:"type"`
		Level     string `json:"level"`
		Component string `json:"component"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("general record is not valid JSON: %v\nrecord: %q", err, encoded)
	}
	if decoded.Schema != 1 || decoded.Type != "general" || decoded.Level != "warning" {
		t.Fatalf("unexpected common fields: %+v", decoded)
	}
	wantMessage := "line one\nline two\t\x1b[31m\ufffd"
	if decoded.Message != wantMessage {
		t.Fatalf("message = %q, want %q", decoded.Message, wantMessage)
	}
}

func TestNewDNSEventOwnsAnswerSnapshot(t *testing.T) {
	answers := []string{"192.0.2.1", "2001:db8::1"}
	event := corelog.NewDNSEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 15, 2, 3, 0, time.UTC),
		Severity:  corelog.Severity_Info,
		Component: "app/dns",
	}, corelog.DNSFields{
		Server:  "1.1.1.1:53",
		Domain:  "example.com",
		Answers: answers,
		Status:  "answer",
		Elapsed: 1250 * time.Microsecond,
	})

	answers[0] = "203.0.113.99"
	answers = append(answers, "198.51.100.10")

	got := string((corelog.JSONEncoder{}).Append(nil, event))
	want := "{\"schema\":1,\"timestamp\":\"2026-07-18T15:02:03Z\",\"type\":\"dns\",\"level\":\"info\",\"component\":\"app/dns\",\"server\":\"1.1.1.1:53\",\"domain\":\"example.com\",\"answers\":[\"192.0.2.1\",\"2001:db8::1\"],\"status\":\"answer\",\"elapsed_ms\":1}\n"
	if got != want {
		t.Fatalf("DNS snapshot mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestJSONEncoderOmitsEmptyOptionalFields(t *testing.T) {
	event := corelog.NewGeneralEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 15, 3, 4, 0, time.UTC),
		Severity:  corelog.Severity_Error,
	}, "failed")

	got := string((corelog.JSONEncoder{}).Append(nil, event))
	want := "{\"schema\":1,\"timestamp\":\"2026-07-18T15:03:04Z\",\"type\":\"general\",\"level\":\"error\",\"message\":\"failed\"}\n"
	if got != want {
		t.Fatalf("minimal general record mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestJSONEncoderEncodesInternalEvent(t *testing.T) {
	event := corelog.NewInternalEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 15, 3, 5, 0, time.UTC),
		Severity:  corelog.Severity_Error,
		Component: "common/log",
	}, "output failed")

	got := string((corelog.JSONEncoder{}).Append(nil, event))
	want := "{\"schema\":1,\"timestamp\":\"2026-07-18T15:03:05Z\",\"type\":\"internal\",\"level\":\"error\",\"component\":\"common/log\",\"message\":\"output failed\"}\n"
	if got != want {
		t.Fatalf("internal record mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestJSONEncoderAllocationBudgetWithCallerCapacity(t *testing.T) {
	event := corelog.NewAccessEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 15, 4, 5, 0, time.UTC),
		Severity:  corelog.Severity_Info,
		Component: "app/dispatcher",
		SessionID: 43,
	}, corelog.AccessFields{
		Source:      "tcp:192.0.2.10:51000",
		Destination: "tcp:example.com:443",
		Network:     "tcp",
		Status:      corelog.AccessAccepted,
		Inbound:     "vless-in",
		Outbound:    "DIRECT",
	})
	encoder := corelog.JSONEncoder{}
	buffer := make([]byte, 0, 512)

	allocations := testing.AllocsPerRun(1000, func() {
		buffer = encoder.Append(buffer[:0], event)
	})
	if allocations != 0 {
		t.Fatalf("JSON encoding allocations = %.0f, want 0", allocations)
	}
}

var jsonEncoderBenchmarkBytes int

func BenchmarkJSONEncoderAccess(b *testing.B) {
	event := corelog.NewAccessEvent(corelog.EventMetadata{
		Timestamp: time.Date(2026, time.July, 18, 15, 4, 5, 0, time.UTC),
		Severity:  corelog.Severity_Info,
		Component: "app/dispatcher",
		SessionID: 43,
	}, corelog.AccessFields{
		Source:      "tcp:192.0.2.10:51000",
		Destination: "tcp:example.com:443",
		Network:     "tcp",
		Status:      corelog.AccessAccepted,
		Inbound:     "vless-in",
		Outbound:    "DIRECT",
	})
	encoder := corelog.JSONEncoder{}
	buffer := make([]byte, 0, 512)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		buffer = encoder.Append(buffer[:0], event)
	}
	jsonEncoderBenchmarkBytes = len(buffer)
}
