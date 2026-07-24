package log

import (
	"sync"
	"testing"
)

type performanceLogHandler struct{}

func (*performanceLogHandler) Handle(Message)        {}
func (*performanceLogHandler) Enabled(Severity) bool { return true }

type performanceLogWriter struct{}

func (*performanceLogWriter) Write(string) error     { return nil }
func (*performanceLogWriter) Close() error           { return nil }
func (*performanceLogWriter) WriteLine(string) error { return nil }

var (
	performanceLogMessage    = &GeneralMessage{Severity: Severity_Info, Content: "benchmark"}
	accessMessageStringSink  string
	generalMessageStringSink string
)

func BenchmarkRecord(b *testing.B) {
	RegisterHandler(new(performanceLogHandler))
	b.ReportAllocs()
	for b.Loop() {
		Record(performanceLogMessage)
	}
}

func BenchmarkRecordParallel(b *testing.B) {
	RegisterHandler(new(performanceLogHandler))
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Record(performanceLogMessage)
		}
	})
}

func TestRecordAllocationBudget(t *testing.T) {
	RegisterHandler(new(performanceLogHandler))
	allocations := testing.AllocsPerRun(1000, func() {
		Record(performanceLogMessage)
	})
	if allocations != 0 {
		t.Fatalf("Record allocations = %.0f, want 0", allocations)
	}
}

func TestConcurrentRegisterAndRecord(t *testing.T) {
	const iterations = 1000
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for range iterations {
			RegisterHandler(new(performanceLogHandler))
		}
	}()
	go func() {
		defer wait.Done()
		for range iterations {
			Record(performanceLogMessage)
		}
	}()
	wait.Wait()
}

func BenchmarkAccessMessageString(b *testing.B) {
	message := &AccessMessage{
		From:   "192.0.2.1:12345",
		To:     "example.com:443",
		Status: AccessAccepted,
		Reason: "routed",
		Email:  "user@example.com",
		Detour: "vless-in -> DIRECT",
	}
	b.ReportAllocs()
	for b.Loop() {
		accessMessageStringSink = message.String()
	}
}

func BenchmarkAcceptedAccessMessageString(b *testing.B) {
	message := &AccessMessage{
		From:   "192.0.2.1:12345",
		To:     "example.com:443",
		Status: AccessAccepted,
		Reason: "",
		Email:  "user@example.com",
		Detour: "vless-in -> DIRECT",
	}
	b.ReportAllocs()
	for b.Loop() {
		accessMessageStringSink = message.String()
	}
}

func BenchmarkAcceptedTypedAccessMessageString(b *testing.B) {
	message := &AccessMessage{
		FromString: "192.0.2.1:12345",
		ToString:   "tcp:example.com:443",
		Status:     AccessAccepted,
		Email:      "user@example.com",
		Detour:     "vless-in -> DIRECT",
	}
	b.ReportAllocs()
	for b.Loop() {
		accessMessageStringSink = message.String()
	}
}

func BenchmarkAcceptedAccessReason(b *testing.B) {
	for _, benchmark := range []struct {
		name   string
		reason any
	}{
		{name: "empty_string", reason: ""},
		{name: "nil", reason: nil},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			message := &AccessMessage{From: "source", To: "target", Status: AccessAccepted, Reason: benchmark.reason}
			b.ReportAllocs()
			for b.Loop() {
				accessMessageStringSink = message.String()
			}
		})
	}
}

func TestAccessMessageStringFormat(t *testing.T) {
	message := &AccessMessage{
		From: "source", To: "target", Status: AccessAccepted,
		Reason: "reason", Email: "user", Detour: "in -> out",
	}
	want := "from source accepted target [in -> out] reason email: user"
	if got := message.String(); got != want {
		t.Fatalf("AccessMessage.String() = %q, want %q", got, want)
	}
}

func BenchmarkGeneralMessageString(b *testing.B) {
	message := &GeneralMessage{Severity: Severity_Warning, Content: "benchmark warning"}
	b.ReportAllocs()
	for b.Loop() {
		generalMessageStringSink = message.String()
	}
}

func TestGeneralMessageStringFormat(t *testing.T) {
	message := &GeneralMessage{Severity: Severity_Warning, Content: "warning"}
	if got, want := message.String(), "[Warning] warning"; got != want {
		t.Fatalf("GeneralMessage.String() = %q, want %q", got, want)
	}
}

func BenchmarkWriteLogMessage(b *testing.B) {
	writer := new(performanceLogWriter)
	message := &GeneralMessage{Severity: Severity_Warning, Content: "benchmark warning"}
	b.ReportAllocs()
	for b.Loop() {
		if err := writeLogMessage(writer, message); err != nil {
			b.Fatal(err)
		}
	}
}
