package buf

import (
	"bytes"
	"syscall"
	"testing"
)

var bufferedReaderBenchmarkSink *BufferedReader
var readerBenchmarkSink Reader

type benchmarkRawConn struct{}

func (benchmarkRawConn) Control(func(uintptr)) error    { return nil }
func (benchmarkRawConn) Read(func(uintptr) bool) error  { return nil }
func (benchmarkRawConn) Write(func(uintptr) bool) error { return nil }

var _ syscall.RawConn = benchmarkRawConn{}

func BenchmarkBufferedReaderLifecycle(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		reader := NewPooledBufferedReader(nil, nil)
		bufferedReaderBenchmarkSink = reader
		reader.Release()
	}
}

func TestPooledReaderAllocationBudget(t *testing.T) {
	underlying := bytes.NewReader(nil)
	allocations := testing.AllocsPerRun(1000, func() {
		reader := NewPooledReader(underlying)
		readerBenchmarkSink = reader
		ReleasePooledReader(reader)
	})
	if allocations != 0 {
		t.Fatalf("pooled reader lifecycle allocations = %.0f, want zero", allocations)
	}
}

func BenchmarkReaderLifecycle(b *testing.B) {
	underlying := bytes.NewReader(nil)
	b.Run("current-single", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			readerBenchmarkSink = NewReader(underlying)
		}
	})
	b.Run("pooled-single", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			reader := NewPooledReader(underlying)
			readerBenchmarkSink = reader
			ReleasePooledReader(reader)
		}
	})
	b.Run("current-readv", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			readerBenchmarkSink = NewReadVReader(underlying, benchmarkRawConn{}, nil)
		}
	})
	b.Run("pooled-readv", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			reader := NewPooledReadVReader(underlying, benchmarkRawConn{}, nil)
			readerBenchmarkSink = reader
			ReleasePooledReadVReader(reader)
		}
	})
}
