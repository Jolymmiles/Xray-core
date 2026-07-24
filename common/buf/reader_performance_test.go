package buf

import (
	"bytes"
	"io"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common"
)

var (
	bufferedReaderBenchmarkSink *BufferedReader
	readerBenchmarkSink         Reader
)

type benchmarkRawConn struct{}

func (benchmarkRawConn) Control(func(uintptr)) error    { return nil }
func (benchmarkRawConn) Read(func(uintptr) bool) error  { return nil }
func (benchmarkRawConn) Write(func(uintptr) bool) error { return nil }

var _ syscall.RawConn = benchmarkRawConn{}

type benchmarkClosableReader struct{}

func (*benchmarkClosableReader) Read([]byte) (int, error) { return 0, io.EOF }
func (*benchmarkClosableReader) Close() error             { return nil }

func BenchmarkBufferedReaderLifecycle(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		reader := NewPooledBufferedReader(nil, nil)
		bufferedReaderBenchmarkSink = reader
		reader.Release()
	}
}

// BenchmarkReaderInterrupt measures the mux finish/teardown path:
// common.Interrupt(*BufferedReader) → single/pooled reader → underlying Close.
func BenchmarkReaderInterrupt(b *testing.B) {
	underlying := new(benchmarkClosableReader)

	b.Run("single", func(b *testing.B) {
		reader := NewReader(underlying)
		b.ReportAllocs()
		for b.Loop() {
			_ = common.Interrupt(reader)
		}
	})
	b.Run("pooled-single", func(b *testing.B) {
		reader := NewPooledReader(underlying)
		b.ReportAllocs()
		for b.Loop() {
			_ = common.Interrupt(reader)
		}
		ReleasePooledReader(reader)
	})
	b.Run("buffered", func(b *testing.B) {
		reader := &BufferedReader{Reader: NewReader(underlying)}
		b.ReportAllocs()
		for b.Loop() {
			reader.Interrupt()
		}
	})
	b.Run("pooled-buffered", func(b *testing.B) {
		inner := NewPooledReader(underlying)
		reader := NewPooledBufferedReader(inner, nil)
		b.ReportAllocs()
		for b.Loop() {
			reader.Interrupt()
		}
		reader.Release()
	})
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
