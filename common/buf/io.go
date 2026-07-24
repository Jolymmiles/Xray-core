package buf

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Reader extends io.Reader with MultiBuffer.
type Reader interface {
	// ReadMultiBuffer reads content from underlying reader, and put it into a MultiBuffer.
	ReadMultiBuffer() (MultiBuffer, error)
}

// ErrReadTimeout is an error that happens with IO timeout.
var ErrReadTimeout = errors.New("IO timeout")

// TimeoutReader is a reader that returns error if Read() operation takes longer than the given timeout.
type TimeoutReader interface {
	Reader
	ReadMultiBufferTimeout(time.Duration) (MultiBuffer, error)
}

type TimeoutWrapperReader struct {
	Reader
	stats.Counter
	mb   MultiBuffer
	err  error
	done chan struct{}
}

func (r *TimeoutWrapperReader) ReadMultiBuffer() (MultiBuffer, error) {
	if r.done != nil {
		<-r.done
		r.done = nil
		if r.Counter != nil {
			r.Counter.Add(int64(r.mb.Len()))
		}
		return r.mb, r.err
	}
	r.mb, r.err = r.Reader.ReadMultiBuffer()
	if r.Counter != nil {
		r.Counter.Add(int64(r.mb.Len()))
	}
	return r.mb, r.err
}

func (r *TimeoutWrapperReader) ReadMultiBufferTimeout(duration time.Duration) (MultiBuffer, error) {
	if r.done == nil {
		r.done = make(chan struct{})
		go func() {
			r.mb, r.err = r.Reader.ReadMultiBuffer()
			close(r.done)
		}()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-r.done:
		r.done = nil
		if r.Counter != nil {
			r.Counter.Add(int64(r.mb.Len()))
		}
		return r.mb, r.err
	case <-timer.C:
		return nil, nil
	}
}

// Writer extends io.Writer with MultiBuffer.
type Writer interface {
	// WriteMultiBuffer writes a MultiBuffer into underlying writer.
	WriteMultiBuffer(MultiBuffer) error
}

type (
	pooledSingleReader struct{ SingleReader }
	pooledPacketReader struct{ PacketReader }
)

var (
	pooledSingleReaders sync.Pool
	pooledPacketReaders sync.Pool
)

func newPooledSingleReader(reader io.Reader) Reader {
	pooled, _ := pooledSingleReaders.Get().(*pooledSingleReader)
	if pooled == nil {
		pooled = new(pooledSingleReader)
	}
	pooled.Reader = reader
	return pooled
}

func newPooledPacketReader(reader io.Reader) Reader {
	pooled, _ := pooledPacketReaders.Get().(*pooledPacketReader)
	if pooled == nil {
		pooled = new(pooledPacketReader)
	}
	pooled.Reader = reader
	return pooled
}

// WriteAllBytes ensures all bytes are written into the given writer.
func WriteAllBytes(writer io.Writer, payload []byte, c stats.Counter) error {
	wc := 0
	defer func() {
		if c != nil {
			c.Add(int64(wc))
		}
	}()

	for len(payload) > 0 {
		n, err := writer.Write(payload)
		wc += n
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func isPacketReader(reader io.Reader) bool {
	_, ok := reader.(net.PacketConn)
	return ok
}

// NewReader creates a new Reader.
// The Reader instance doesn't take the ownership of reader.
func NewReader(reader io.Reader) Reader {
	if mr, ok := reader.(Reader); ok {
		return mr
	}
	if statConn, ok := reader.(*stat.CounterConnection); ok {
		if isPacketReader(statConn.Connection) {
			return &PacketReader{Reader: reader}
		}
		if runtime.GOOS == "linux" && useReadV() {
			if sc, ok := statConn.Connection.(syscall.Conn); ok {
				rawConn, err := sc.SyscallConn()
				if err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to get sysconn")
				} else {
					return NewReadVReader(statConn.Connection, rawConn, statConn.ReadCounter)
				}
			}
		}
		return &SingleReader{Reader: reader}
	}

	if isPacketReader(reader) {
		return &PacketReader{
			Reader: reader,
		}
	}

	_, isFile := reader.(*os.File)
	if !isFile && useReadV() {
		if sc, ok := reader.(syscall.Conn); ok {
			rawConn, err := sc.SyscallConn()
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to get sysconn")
			} else {
				return NewReadVReader(reader, rawConn, nil)
			}
		}
	}

	return &SingleReader{
		Reader: reader,
	}
}

// NewPooledReader is an opt-in variant of NewReader for connection-scoped
// users whose owner calls ReleasePooledReader when the reader is unreachable.
func NewPooledReader(reader io.Reader) Reader {
	if mr, ok := reader.(Reader); ok {
		return mr
	}
	if statConn, ok := reader.(*stat.CounterConnection); ok {
		if isPacketReader(statConn.Connection) {
			return newPooledPacketReader(reader)
		}
		if runtime.GOOS == "linux" && useReadV() {
			if sc, ok := statConn.Connection.(syscall.Conn); ok {
				rawConn, err := sc.SyscallConn()
				if err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to get sysconn")
				} else {
					return NewPooledReadVReader(statConn.Connection, rawConn, statConn.ReadCounter)
				}
			}
		}
		return newPooledSingleReader(reader)
	}
	if isPacketReader(reader) {
		return newPooledPacketReader(reader)
	}
	_, isFile := reader.(*os.File)
	if !isFile && useReadV() {
		if sc, ok := reader.(syscall.Conn); ok {
			rawConn, err := sc.SyscallConn()
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to get sysconn")
			} else {
				return NewPooledReadVReader(reader, rawConn, nil)
			}
		}
	}
	return newPooledSingleReader(reader)
}

// ReleasePooledReader clears retained connection state and returns readers
// created by NewPooledReader to their pools. Other Reader values are ignored.
func ReleasePooledReader(reader Reader) {
	switch reader := reader.(type) {
	case *pooledSingleReader:
		reader.Reader = nil
		pooledSingleReaders.Put(reader)
	case *pooledPacketReader:
		reader.Reader = nil
		pooledPacketReaders.Put(reader)
	default:
		if reader, ok := reader.(interface{ releasePooledReader() }); ok {
			reader.releasePooledReader()
		}
	}
}

// NewPacketReader creates a new PacketReader based on the given reader.
func NewPacketReader(reader io.Reader) Reader {
	if mr, ok := reader.(Reader); ok {
		return mr
	}

	return &PacketReader{
		Reader: reader,
	}
}

func isPacketWriter(writer io.Writer) bool {
	if _, ok := writer.(net.PacketConn); ok {
		return true
	}

	// If the writer doesn't implement syscall.Conn, it is probably not a TCP connection.
	if _, ok := writer.(syscall.Conn); !ok {
		return true
	}
	return false
}

type (
	pooledSequentialWriter    struct{ SequentialWriter }
	pooledBufferToBytesWriter struct{ BufferToBytesWriter }
)

var (
	pooledSequentialWriters    sync.Pool
	pooledBufferToBytesWriters sync.Pool
)

// NewPooledWriter is an opt-in variant of NewWriter for connection-scoped
// users that call ReleasePooledWriter after the writer is no longer reachable.
func NewPooledWriter(writer io.Writer) Writer {
	if mw, ok := writer.(Writer); ok {
		return mw
	}
	if statConn, ok := writer.(*stat.CounterConnection); ok {
		if isPacketWriter(statConn.Connection) {
			pooled, _ := pooledSequentialWriters.Get().(*pooledSequentialWriter)
			if pooled == nil {
				pooled = new(pooledSequentialWriter)
			}
			pooled.Writer = writer
			return pooled
		}
		pooled, _ := pooledBufferToBytesWriters.Get().(*pooledBufferToBytesWriter)
		if pooled == nil {
			pooled = new(pooledBufferToBytesWriter)
		}
		pooled.Writer = statConn.Connection
		pooled.counter = statConn.WriteCounter
		return pooled
	}
	if isPacketWriter(writer) {
		pooled, _ := pooledSequentialWriters.Get().(*pooledSequentialWriter)
		if pooled == nil {
			pooled = new(pooledSequentialWriter)
		}
		pooled.Writer = writer
		return pooled
	}
	pooled, _ := pooledBufferToBytesWriters.Get().(*pooledBufferToBytesWriter)
	if pooled == nil {
		pooled = new(pooledBufferToBytesWriter)
	}
	pooled.Writer = writer
	return pooled
}

// ReleasePooledWriter clears retained connection state and returns writers
// created by NewPooledWriter to their pools. Other Writer values are ignored.
func ReleasePooledWriter(writer Writer) {
	switch writer := writer.(type) {
	case *pooledSequentialWriter:
		writer.Writer = nil
		pooledSequentialWriters.Put(writer)
	case *pooledBufferToBytesWriter:
		writer.Writer = nil
		writer.counter = nil
		clear(writer.inline[:])
		writer.cache = writer.cache[:0]
		pooledBufferToBytesWriters.Put(writer)
	}
}

// NewWriter creates a new Writer.
func NewWriter(writer io.Writer) Writer {
	if mw, ok := writer.(Writer); ok {
		return mw
	}

	if statConn, ok := writer.(*stat.CounterConnection); ok {
		if isPacketWriter(statConn.Connection) {
			return &SequentialWriter{Writer: writer}
		}
		return &BufferToBytesWriter{
			Writer:  statConn.Connection,
			counter: statConn.WriteCounter,
		}
	}

	if isPacketWriter(writer) {
		return &SequentialWriter{
			Writer: writer,
		}
	}
	return &BufferToBytesWriter{
		Writer: writer,
	}
}
