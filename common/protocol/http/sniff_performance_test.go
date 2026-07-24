package http

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
)

var sniffHTTPBenchmarkSink *SniffHeader

var (
	sniffHTTPBenchmarkPayload     = []byte("GET /index HTTP/1.1\r\nHost: example.com\r\nUser-Agent: benchmark\r\nAccept: */*\r\n\r\n")
	sniffHTTPUppercaseHostPayload = []byte("GET /index HTTP/1.1\r\nHost: EXAMPLE.COM\r\nUser-Agent: benchmark\r\nAccept: */*\r\n\r\n")
)

type countingValueContext struct {
	context.Context
	calls int
}

func (c *countingValueContext) Value(key any) any {
	c.calls++
	return c.Context.Value(key)
}

func TestSniffHTTPAcceptsMixedCaseMethod(t *testing.T) {
	header, err := SniffHTTP([]byte("gEt / HTTP/1.1\r\nhOsT: example.com\r\n\r\n"), context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if header.Domain() != "example.com" {
		t.Fatalf("domain = %q", header.Domain())
	}
}

func TestSniffHTTPStopsAtFirstHostHeader(t *testing.T) {
	header, err := SniffHTTP([]byte("GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n"), context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if header.Domain() != "first.example" {
		t.Fatalf("domain = %q, want first.example", header.Domain())
	}
}

func TestSniffHTTPRejectsMethodBeforeContextLookup(t *testing.T) {
	ctx := &countingValueContext{Context: context.Background()}
	if _, err := SniffHTTP([]byte("\x16\x03\x01not-http"), ctx); err == nil {
		t.Fatal("SniffHTTP unexpectedly accepted TLS payload")
	}
	if ctx.calls != 0 {
		t.Fatalf("context Value called %d times, want 0", ctx.calls)
	}
}

func BenchmarkSniffHTTPRejectNonHTTP(b *testing.B) {
	ctx := session.ContextWithContent(context.Background(), new(session.Content))
	payload := []byte("\x16\x03\x01not-http")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := SniffHTTP(payload, ctx); err == nil {
			b.Fatal("SniffHTTP unexpectedly accepted TLS payload")
		}
	}
}

func TestSniffHTTPNoAttributesAllocationBudget(t *testing.T) {
	ctx := context.Background()
	allocations := testing.AllocsPerRun(1000, func() {
		header, err := SniffHTTP(sniffHTTPBenchmarkPayload, ctx)
		if err != nil {
			t.Fatal(err)
		}
		sniffHTTPBenchmarkSink = header
	})
	if allocations > 2 {
		t.Fatalf("SniffHTTP allocations = %.0f, want at most 2", allocations)
	}
}

func BenchmarkSniffHTTPNoAttributes(b *testing.B) {
	benchmarkSniffHTTPNoAttributes(b, sniffHTTPBenchmarkPayload)
}

func BenchmarkSniffHTTPUppercaseHostNoAttributes(b *testing.B) {
	benchmarkSniffHTTPNoAttributes(b, sniffHTTPUppercaseHostPayload)
}

func benchmarkSniffHTTPNoAttributes(b *testing.B, payload []byte) {
	b.Helper()
	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		header, err := SniffHTTP(payload, ctx)
		if err != nil {
			b.Fatal(err)
		}
		sniffHTTPBenchmarkSink = header
	}
}

func BenchmarkSniffHTTPAttributes(b *testing.B) {
	content := new(session.Content)
	ctx := session.ContextWithContent(context.Background(), content)
	b.ReportAllocs()
	b.SetBytes(int64(len(sniffHTTPBenchmarkPayload)))
	for b.Loop() {
		content.Attributes = nil
		header, err := SniffHTTP(sniffHTTPBenchmarkPayload, ctx)
		if err != nil {
			b.Fatal(err)
		}
		sniffHTTPBenchmarkSink = header
	}
}

func TestSniffHTTPAttributesAllocationBudget(t *testing.T) {
	content := new(session.Content)
	ctx := session.ContextWithContent(context.Background(), content)
	allocations := testing.AllocsPerRun(1000, func() {
		content.Attributes = nil
		header, err := SniffHTTP(sniffHTTPBenchmarkPayload, ctx)
		if err != nil {
			t.Fatal(err)
		}
		sniffHTTPBenchmarkSink = header
	})
	if allocations > 4 {
		t.Fatalf("SniffHTTP attributes allocations = %.0f, want at most 4", allocations)
	}
}

func TestSniffHTTPAttributesOwnValues(t *testing.T) {
	payload := append([]byte(nil), sniffHTTPBenchmarkPayload...)
	content := new(session.Content)
	ctx := session.ContextWithContent(context.Background(), content)
	header, err := SniffHTTP(payload, ctx)
	if err != nil {
		t.Fatal(err)
	}
	clear(payload)
	for key, want := range map[string]string{
		"host":       "example.com",
		"user-agent": "benchmark",
		"accept":     "*/*",
		":method":    "GET",
		":path":      "/index",
	} {
		if got := content.Attributes[key]; got != want {
			t.Fatalf("attribute %q = %q, want %q", key, got, want)
		}
	}
	if got := header.Domain(); got != "example.com" {
		t.Fatalf("domain = %q", got)
	}
}

func TestSniffHTTPSkipsAttributesWhenRouterDoesNotNeedThem(t *testing.T) {
	content := &session.Content{SkipSniffingAttributes: true}
	ctx := session.ContextWithContent(context.Background(), content)
	header, err := SniffHTTP(sniffHTTPBenchmarkPayload, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if header.Domain() != "example.com" {
		t.Fatalf("domain = %q, want example.com", header.Domain())
	}
	if content.Attributes != nil {
		t.Fatalf("attributes = %v, want nil", content.Attributes)
	}
}
