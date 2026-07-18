package http

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
)

var parseHostBenchmarkSink net.Destination

func TestParseHostDomainWithoutPortAllocationBudget(t *testing.T) {
	allocations := testing.AllocsPerRun(1000, func() {
		destination, err := ParseHost("example.com", 80)
		if err != nil {
			t.Fatal(err)
		}
		parseHostBenchmarkSink = destination
	})
	if allocations > 1 {
		t.Fatalf("ParseHost domain allocations = %.0f, want at most 1", allocations)
	}
}

func TestParseHostIPv4WithPortAllocationBudget(t *testing.T) {
	allocations := testing.AllocsPerRun(1000, func() {
		destination, err := ParseHost("127.0.0.1:8080", 80)
		if err != nil {
			t.Fatal(err)
		}
		parseHostBenchmarkSink = destination
	})
	if allocations > 2 {
		t.Fatalf("ParseHost IPv4 allocations = %.0f, want at most 2", allocations)
	}
}

func BenchmarkParseHostDomainWithoutPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		destination, err := ParseHost("example.com", 80)
		if err != nil {
			b.Fatal(err)
		}
		parseHostBenchmarkSink = destination
	}
}

func BenchmarkParseHostIPv4WithPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		destination, err := ParseHost("127.0.0.1:8080", 80)
		if err != nil {
			b.Fatal(err)
		}
		parseHostBenchmarkSink = destination
	}
}
